//! Native captures and document-scoped ACKs for optional same-origin storage.
use crate::{SolveApp, file_providers::Action};
use solidcraft_engine::Session;

/// Immutable source session; the model, embedded canvases and document share their existing COW data.
pub(crate) struct Captured {
    pub uid: u64,
    pub session: Session,
}

pub(crate) fn save(app: &mut SolveApp, save_as: bool) {
    if app.file_picker_busy() || app.file_load.busy() {
        return;
    }
    if !app.session.doc.links.is_empty() {
        app.set_status(app.tr("provider.external_links").to_owned(), true);
        return;
    }
    if crate::browser::needs_capture(app, crate::browser::SAVE) {
        app.tree.capture_prompt = Some(crate::browser::SAVE.into());
        return;
    }
    let host = app.file_providers.clone();
    let source = app.session.scratch();
    let (uid, revision) = (source.uid, source.revision);
    let name = host.bound_filename(uid).unwrap_or_else(|| format!("{}.sc", app.session.save_as_name()));
    // The official container writer uses only warm geometry and preserves the native document's
    // embedded data. It does not evaluate the model or write a synthetic provider filesystem path.
    let encoded = source.design_container(solidcraft_engine::io::DesignCompression::Fast, true, true);
    let result = encoded
        .map_err(|error| error.to_string())
        .and_then(|bytes| host.begin(vec![Captured { uid, session: source }], uid, revision, name, bytes, save_as));
    match result {
        Ok(_) => app.set_status(app.tr("provider.choose_destination").to_owned(), false),
        Err(error) => {
            log::warn!("file provider capture failed: {error}");
            app.set_status(app.tr("provider.save_failed").to_owned(), true);
        }
    }
}

pub(crate) fn tick(app: &mut SolveApp) {
    let host = app.file_providers.clone();
    if !host.connected() {
        return;
    }
    // Only this synchronous adapter may pass the picker guard while applying its owned request.
    app.file_provider_applying = true;
    for action in host.take_actions() {
        match action {
            Action::Save { request, capture, status, resource } => {
                let alive = crate::documents::index_by_uid(app, capture.doc).is_some();
                if status == "saved" {
                    for snapshot in &capture.snapshots {
                        if let Some(session) = crate::documents::session_by_uid_mut(app, snapshot.uid) {
                            session.mark_saved_capture(&snapshot.session);
                            // Resource IDs remain opaque. The provider is the origin of this save.
                            session.path = None;
                            session.disk = None;
                        }
                    }
                    app.set_status(app.tr("provider.saved").to_owned(), false);
                } else if status == "failed" {
                    app.set_status(app.tr("provider.save_failed").to_owned(), true);
                }
                host.finish_save(&request, &capture, &status, &resource, alive);
            }
            Action::Open { request, resource, name, bytes } => {
                let result = if let Some(index) = host.bound_document(&resource).and_then(|uid| crate::documents::index_by_uid(app, uid)) {
                    crate::documents::switch(app, index);
                    Ok(app.session.uid)
                } else {
                    open_native(&bytes).and_then(|session| {
                        let uid = session.uid;
                        crate::documents::open_tab(app, session)?;
                        app.home.open = false;
                        Ok(uid)
                    })
                };
                if let Err(error) = &result {
                    log::warn!("file provider open failed: {error}");
                    app.set_status(app.tr("provider.open_failed").to_owned(), true);
                }
                host.finish_open(&request, &resource, &name, result);
            }
        }
    }
    app.file_provider_applying = false;
    if !host.busy() {
        crate::documents::saved_for_close(app);
    }
    let documents = std::iter::once(&app.session).chain(app.docs.background());
    host.refresh(documents.map(|session| (session.uid, session.revision, session.doc.name.clone(), session.is_dirty())).collect());
}

/// Content in the existing Home/Menu containers, with the same native file rows and catalog text.
pub(crate) fn recent_ui(app: &mut SolveApp, ui: &mut egui::Ui) {
    let host = app.file_providers.clone();
    let Some((label, resources)) = host.recent_data() else { return };
    let heading = crate::i18n::format("provider.recents", &[("provider", &label)]);
    let spacing = crate::theme::Tokens::get().space_12;
    crate::ui_kit::FileView::section(ui, &heading, spacing, |ui| {
        if resources.is_empty() {
            ui.label(app.tr("provider.no_recents"));
        }
        for resource in resources {
            if crate::context_menu::button(ui, &resource.name, "open").on_hover_text(&resource.updated_at).clicked() {
                if let Err(error) = host.request_open(&resource.id) {
                    log::warn!("file provider request failed: {error}");
                    app.set_status(app.tr("provider.open_failed").to_owned(), true);
                }
                ui.ctx().request_repaint();
            }
        }
    });
    ui.label(app.tr("provider.device_recents"));
}

fn read_native(bytes: &[u8]) -> Result<(solidcraft_engine::doc::Document, Option<solidcraft_engine::doc::SavedModel>), String> {
    if solidcraft_engine::io::is_design_container(bytes) {
        let mut reader = solidcraft_engine::io::DesignContainerReader::new(std::io::Cursor::new(bytes)).map_err(|error| error.to_string())?;
        let geometry = reader.geometry();
        let document = reader.read_document().map_err(|error| error.to_string())?;
        Ok((document, geometry))
    } else {
        solidcraft_engine::io::read_design(bytes).map(|document| (document, None)).map_err(|error| error.to_string())
    }
}

fn open_native(bytes: &[u8]) -> Result<Session, String> {
    // Native imports are hostile. Keep the same last-resort unwind guard as command execution;
    // the native reader and individual geometry operations retain their own limits/guards.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (document, saved) = read_native(bytes)?;
        if !document.links.is_empty() {
            return Err("linked designs require independent storage resolution".into());
        }
        Ok(Session::opened(document, saved.as_ref()))
    }))
    .map_err(|_| "native design admission failed".to_string())?
}
