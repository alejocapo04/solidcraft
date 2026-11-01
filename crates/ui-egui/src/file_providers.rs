//! Optional same-origin storage capability. No provider is enabled by default.
//!
//! Requests own immutable native project captures. A host result never selects a live tab,
//! revision, filesystem path or account. This module contains no storage or authentication.
use crate::file_provider_app::Captured as DocState;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

const MAX_BYTES: usize = 80 * 1024 * 1024;
const MAX_PENDING: usize = 16;
const MAX_EVENTS: usize = 64;
const MAX_RESOURCES: usize = 100;
const EXTENSION: &str = ".sc";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Resource {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub updated_at: String,
}
pub struct Event {
    pub metadata: Value,
    pub bytes: Option<Vec<u8>>,
}
#[derive(Clone, PartialEq, Eq)]
struct Identity {
    provider_id: String,
    label: String,
    namespace: String,
}
/// The exact states encoded at Save, including a main document's branch tabs where applicable.
pub(crate) struct Capture {
    pub doc: u64,
    pub revision: u64,
    pub snapshots: Vec<DocState>,
    pub name: String,
    intent: String,
    destination: String,
    bytes: Option<Vec<u8>>,
}
pub(crate) enum Action {
    Save { request: String, capture: Capture, status: String, resource: String },
    Open { request: String, resource: String, name: String, bytes: Vec<u8> },
}
#[derive(Default)]
struct State {
    provider: Option<Identity>,
    enabled: bool,
    nonce: String,
    serial: u64,
    connection: String,
    resources: Vec<Resource>,
    bindings: HashMap<u64, String>,
    names: HashMap<u64, String>,
    dialogs: HashMap<String, Capture>,
    pending: HashMap<String, Capture>,
    opens: HashMap<String, String>,
    queued_opens: HashSet<String>,
    actions: Vec<Action>,
    events: Vec<Event>,
    documents: Value,
}
impl State {
    fn busy(&self) -> bool {
        !self.dialogs.is_empty() || !self.pending.is_empty() || !self.opens.is_empty() || !self.actions.is_empty()
    }
    fn next(&mut self, kind: &str) -> Result<String, String> {
        if self.nonce.is_empty() {
            return Err("file provider session is not initialized".into());
        }
        self.serial = self.serial.checked_add(1).ok_or("file provider request counter exhausted")?;
        Ok(format!("{}-{kind}-{}", self.nonce, self.serial))
    }
    fn event(&mut self, mut metadata: Value, bytes: Option<Vec<u8>>) {
        if let (Some(provider), Some(fields)) = (&self.provider, metadata.as_object_mut()) {
            fields.insert("providerId".into(), provider.provider_id.clone().into());
            fields.insert("namespace".into(), provider.namespace.clone().into());
            fields.insert("connectionId".into(), self.connection.clone().into());
        }
        self.events.push(Event { metadata, bytes });
    }
    fn retained_bytes(&self) -> usize {
        let captures = self.dialogs.values().chain(self.pending.values()).map(|p| p.bytes.as_ref().map_or(0, Vec::len));
        let events = self.events.iter().map(|e| e.bytes.as_ref().map_or(0, Vec::len));
        let actions = self.actions.iter().map(|a| match a {
            Action::Open { bytes, .. } => bytes.len(),
            _ => 0,
        });
        captures.chain(events).chain(actions).fold(0, usize::saturating_add)
    }
    fn pending_for(&self, doc: u64) -> bool {
        self.dialogs.values().chain(self.pending.values()).any(|c| c.snapshots.iter().any(|d| d.uid == doc))
            || self.actions.iter().any(|a| matches!(a, Action::Save { capture, .. } if capture.snapshots.iter().any(|d| d.uid == doc)))
    }
}
#[derive(Clone, Default)]
pub struct Host(Arc<Mutex<State>>);
impl Host {
    fn state(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    pub fn set_session(&self, nonce: String) -> Result<(), String> {
        let mut s = self.state();
        if !s.nonce.is_empty() || s.provider.is_some() || !valid_id(&nonce) || nonce.len() < 16 {
            return Err("invalid or already initialized file provider session".into());
        }
        s.nonce = nonce;
        Ok(())
    }
    pub fn connect(&self, provider_id: String, label: String, namespace: String) -> Result<String, String> {
        if !valid_id(&provider_id) || !valid_label(&label) || !valid_id(&namespace) {
            return Err("invalid file provider identity".into());
        }
        let mut s = self.state();
        let identity = Identity { provider_id, label, namespace };
        if let Some(current) = &s.provider {
            return if *current == identity { Ok(s.connection.clone()) } else { Err("unregister before changing provider or account".into()) };
        }
        s.connection = s.next("connection")?;
        s.provider = Some(identity);
        s.enabled = true;
        Ok(s.connection.clone())
    }
    pub fn disconnect(&self) -> Result<(), String> {
        let mut s = self.state();
        if s.busy() {
            return Err("finish or cancel pending provider operations before unregistering".into());
        }
        s.provider = None;
        s.enabled = false;
        s.connection.clear();
        s.resources.clear();
        s.bindings.clear();
        s.names.clear();
        s.events.clear();
        s.documents = Value::Null;
        Ok(())
    }
    pub fn connected(&self) -> bool {
        self.state().provider.is_some()
    }
    pub fn enabled(&self) -> bool {
        let s = self.state();
        s.provider.is_some() && s.enabled
    }
    pub fn set_enabled(&self, enabled: bool) -> Result<(), String> {
        let mut s = self.state();
        if s.provider.is_none() {
            return Err("file provider is not connected".into());
        }
        s.enabled = enabled;
        Ok(())
    }
    pub fn busy(&self) -> bool {
        self.state().busy()
    }
    pub fn pending_for(&self, doc: u64) -> bool {
        self.state().pending_for(doc)
    }
    pub fn bound_document(&self, resource: &str) -> Option<u64> {
        self.state().bindings.iter().find(|(_, r)| r.as_str() == resource).map(|(d, _)| *d)
    }
    pub fn bound_filename(&self, doc: u64) -> Option<String> {
        self.state().names.get(&doc).cloned()
    }
    /// Captures are produced synchronously by the editor before this event is issued.
    pub(crate) fn begin(
        &self,
        snapshots: Vec<DocState>,
        doc: u64,
        revision: u64,
        name: String,
        bytes: Vec<u8>,
        save_as: bool,
    ) -> Result<String, String> {
        let mut s = self.state();
        if s.provider.is_none()
            || !s.enabled
            || !valid_native_name(&name)
            || bytes.is_empty()
            || bytes.len() > MAX_BYTES
            || s.retained_bytes().saturating_add(bytes.len()) > MAX_BYTES
            || s.pending_for(doc)
            || s.dialogs.len() + s.pending.len() >= MAX_PENDING
            || s.events.len() >= MAX_EVENTS
            || snapshots.is_empty()
        {
            return Err("provider unavailable, a save is pending, or capture exceeds 80 MiB".into());
        }
        let request = s.next("dialog")?;
        let intent = if save_as { "saveAs" } else { "save" }.to_string();
        s.event(json!({"type":"saveDialog","requestId":request,"documentId":doc.to_string(),"revision":revision.to_string(),"intent":intent,"filename":name}), None);
        s.dialogs.insert(request.clone(), Capture { doc, revision, snapshots, name, intent, destination: String::new(), bytes: Some(bytes) });
        Ok(request)
    }
    pub fn resolve_dialog(&self, request: &str, destination: &str, name: &str) -> Result<(), String> {
        if !matches!(destination, "provider" | "device" | "cancel") || (destination != "cancel" && !valid_native_name(name)) {
            return Err("choose provider, device or cancel and a native project filename".into());
        }
        let mut s = self.state();
        if s.events.len() >= MAX_EVENTS {
            return Err("provider event queue is full".into());
        }
        let mut capture = s.dialogs.remove(request).ok_or("unknown or completed save dialog")?;
        if destination == "cancel" {
            capture.bytes = None;
            s.actions.push(Action::Save { request: request.into(), capture, status: "cancel".into(), resource: String::new() });
            return Ok(());
        }
        capture.name = name.into();
        capture.destination = destination.into();
        let resource = if capture.intent == "save" { s.bindings.get(&capture.doc).cloned() } else { None };
        let bytes = capture.bytes.take();
        s.event(json!({"type":"save","requestId":request,"documentId":capture.doc.to_string(),"revision":capture.revision.to_string(),"intent":capture.intent,"filename":name,"resourceId":resource,"destination":destination}), bytes);
        s.pending.insert(request.into(), capture);
        Ok(())
    }
    pub fn result(&self, request: String, status: String, resource: String) -> Result<(), String> {
        if !matches!(status.as_str(), "saved" | "download" | "failed" | "cancel") || (!resource.is_empty() && !valid_id(&resource)) {
            return Err("invalid provider result".into());
        }
        let mut s = self.state();
        let capture = s.pending.get(&request).ok_or("unknown or completed save request")?;
        if (status == "saved" && (capture.destination != "provider" || !valid_id(&resource)))
            || (status == "download" && capture.destination != "device")
        {
            return Err("result does not match the chosen destination".into());
        }
        if status == "saved" && s.bindings.iter().any(|(doc, id)| *doc != capture.doc && *id == resource) {
            return Err("resource is bound to another open document".into());
        }
        if status == "saved" && capture.intent == "saveAs" && s.bindings.get(&capture.doc) == Some(&resource) {
            return Err("Save As must produce a distinct resource".into());
        }
        if s.actions.len() >= MAX_PENDING {
            return Err("provider command queue is full".into());
        }
        let capture = s.pending.remove(&request).ok_or("unknown save request")?;
        s.actions.push(Action::Save { request, capture, status, resource });
        Ok(())
    }
    pub fn set_resources(&self, connection: &str, resources: Vec<Resource>) -> Result<(), String> {
        let mut seen = HashSet::new();
        if resources.len() > MAX_RESOURCES
            || resources.iter().any(|r| !valid_id(&r.id) || !valid_native_name(&r.name) || r.updated_at.len() > 100 || !seen.insert(r.id.clone()))
        {
            return Err("invalid native project resource list".into());
        }
        let mut s = self.state();
        if s.provider.is_none() || s.connection != connection {
            return Err("resource list belongs to another connection".into());
        }
        s.resources = resources;
        Ok(())
    }
    pub fn request_open(&self, resource: &str) -> Result<String, String> {
        let mut s = self.state();
        if !s.enabled
            || s.provider.is_none()
            || s.opens.len() >= MAX_PENDING
            || s.events.len() >= MAX_EVENTS
            || !s.resources.iter().any(|r| r.id == resource)
        {
            return Err("resource is unavailable in the current provider account".into());
        }
        let request = s.next("open")?;
        s.opens.insert(request.clone(), resource.into());
        s.event(json!({"type":"openRequested","requestId":request,"resourceId":resource}), None);
        Ok(request)
    }
    pub fn open(&self, request: String, name: String, bytes: Vec<u8>) -> Result<(), String> {
        if !valid_native_name(&name) || bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err("invalid native project resource".into());
        }
        let mut s = self.state();
        if s.actions.len() >= MAX_PENDING || s.retained_bytes().saturating_add(bytes.len()) > MAX_BYTES {
            return Err("provider command queue is full".into());
        }
        if s.queued_opens.contains(&request) {
            return Err("open response already queued".into());
        }
        let resource = s.opens.get(&request).cloned().ok_or("unknown or completed open request")?;
        s.queued_opens.insert(request.clone());
        s.actions.push(Action::Open { request, resource, name, bytes });
        Ok(())
    }
    pub fn cancel_open(&self, request: String, error: String) -> Result<(), String> {
        if error.len() > 1024 {
            return Err("invalid open result".into());
        }
        let mut s = self.state();
        if s.queued_opens.contains(&request) {
            return Err("open response already queued".into());
        }
        if s.events.len() >= MAX_EVENTS {
            return Err("provider event queue is full".into());
        }
        let resource = s.opens.remove(&request).ok_or("unknown or completed open request")?;
        s.event(json!({"type":if error.is_empty(){"openCancelled"}else{"openFailed"},"requestId":request,"resourceId":resource,"error":error}), None);
        Ok(())
    }
    pub(crate) fn take_actions(&self) -> Vec<Action> {
        std::mem::take(&mut self.state().actions)
    }
    pub fn take_events(&self) -> Vec<Event> {
        std::mem::take(&mut self.state().events)
    }
    pub fn snapshot(&self) -> Value {
        let s = self.state();
        json!({"protocolVersion":1,"enabled":s.enabled && s.provider.is_some(),"provider":s.provider.as_ref().map(|p|json!({"id":p.provider_id,"label":p.label,"namespace":p.namespace})),"connectionId":s.connection,"resources":s.resources,"documents":s.documents,"pending":s.busy()})
    }
    pub(crate) fn refresh(&self, docs: Vec<(u64, u64, String, bool)>) {
        let mut s = self.state();
        let live: HashSet<_> = docs.iter().map(|d| d.0).collect();
        s.bindings.retain(|id, _| live.contains(id));
        s.names.retain(|id, _| live.contains(id));
        s.documents = json!(docs.into_iter().map(|(id,rev,name,dirty)|json!({"id":id.to_string(),"revision":rev.to_string(),"name":name,"dirty":dirty,"resourceId":s.bindings.get(&id)})).collect::<Vec<_>>());
    }
    pub(crate) fn finish_save(&self, request: &str, capture: &Capture, status: &str, resource: &str, alive: bool) {
        let mut s = self.state();
        if status == "saved" {
            if alive {
                s.bindings.insert(capture.doc, resource.into());
                s.names.insert(capture.doc, capture.name.clone());
            }
            s.resources.retain(|r| r.id != resource);
            s.resources.insert(0, Resource { id: resource.into(), name: capture.name.clone(), updated_at: String::new() });
            s.resources.truncate(MAX_RESOURCES);
        }
        s.event(json!({"type":match status { "saved"=>"saved", "download"=>"downloaded", "cancel"=>"saveCancelled", _=>"saveFailed" },"requestId":request,"documentId":capture.doc.to_string(),"revision":capture.revision.to_string(),"resourceId":resource,"filename":capture.name,"documentOpen":alive}), None);
    }
    pub(crate) fn finish_open(&self, request: &str, resource: &str, name: &str, result: Result<u64, String>) {
        let mut s = self.state();
        s.opens.remove(request);
        s.queued_opens.remove(request);
        match result {
            Ok(doc) => {
                s.bindings.insert(doc, resource.into());
                s.names.insert(doc, name.into());
                s.event(json!({"type":"opened","requestId":request,"resourceId":resource,"documentId":doc.to_string()}), None);
            }
            Err(error) => s.event(json!({"type":"openFailed","requestId":request,"resourceId":resource,"error":error}), None),
        }
    }
    pub(crate) fn recent_data(&self) -> Option<(String, Vec<Resource>)> {
        let s = self.state();
        s.provider.as_ref().filter(|_| s.enabled).map(|p| (p.label.clone(), s.resources.clone()))
    }
}
fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 160 && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}
fn valid_label(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 100 && !value.chars().any(char::is_control)
}
fn valid_native_name(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 255
        && !value.chars().any(|c| c.is_control() || matches!(c, '/' | '\\'))
        && (value.to_ascii_lowercase().ends_with(EXTENSION) || value.to_ascii_lowercase().ends_with(".solidcraft"))
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use solidcraft_engine::Session;
    fn host() -> Host {
        let h = Host::default();
        h.set_session("0123456789abcdef0123456789abcdef".into()).unwrap();
        h.connect("test".into(), "Test storage".into(), "account-a".into()).unwrap();
        h
    }
    fn capture(h: &Host, save_as: bool) -> (String, u64) {
        let session = Session::default();
        let uid = session.uid;
        let revision = session.revision;
        (h.begin(vec![crate::file_provider_app::Captured { uid, session }], uid, revision, "example.sc".into(), vec![1, 2, 3], save_as).unwrap(), uid)
    }
    #[test]
    fn off_until_explicit_registration_and_session_is_single_use() {
        let h = Host::default();
        assert!(!h.enabled());
        assert!(!h.connected());
        assert!(h.connect("test".into(), "Test".into(), "a".into()).is_err());
        assert!(host().set_session("0123456789abcdef".into()).is_err());
    }
    #[test]
    fn each_save_has_a_choice_and_cancel_never_acknowledges_a_document() {
        let h = host();
        let (request, uid) = capture(&h, false);
        assert_eq!(h.take_events()[0].metadata["type"], "saveDialog");
        assert!(h.pending_for(uid));
        h.resolve_dialog(&request, "cancel", "").unwrap();
        let actions = h.take_actions();
        assert!(matches!(&actions[..],[Action::Save { status, .. }] if status == "cancel"));
        assert!(h.state().bindings.is_empty());
        assert!(h.result(request, "saved".into(), "file".into()).is_err());
    }
    #[test]
    fn durable_ack_owns_its_capture_and_is_single_use() {
        let h = host();
        let (request, uid) = capture(&h, false);
        h.take_events();
        assert!(h.disconnect().is_err());
        h.resolve_dialog(&request, "provider", "durable.sc").unwrap();
        let event = h.take_events().remove(0);
        assert_eq!(event.metadata["type"], "save");
        assert_eq!(event.bytes, Some(vec![1, 2, 3]));
        h.result(request.clone(), "saved".into(), "file-1".into()).unwrap();
        assert!(h.result(request, "saved".into(), "file-1".into()).is_err());
        assert!(matches!(h.take_actions().as_slice(),[Action::Save { capture,resource,.. }] if capture.doc==uid && resource=="file-1"));
    }
    #[test]
    fn replies_cannot_cross_the_chosen_destination_or_an_open_resource_alias() {
        let h = host();
        let (request, uid) = capture(&h, false);
        h.resolve_dialog(&request, "device", "local.sc").unwrap();
        assert!(h.result(request.clone(), "saved".into(), "remote".into()).is_err());
        h.result(request, "download".into(), String::new()).unwrap();
        h.take_actions();
        h.take_events();
        let (request, _) = capture(&h, false);
        h.state().bindings.insert(uid, "already-open".into());
        h.resolve_dialog(&request, "provider", "new.sc").unwrap();
        assert!(h.result(request, "saved".into(), "already-open".into()).is_err());
    }
    #[test]
    fn unregister_clears_cached_account_documents_before_reconnect() {
        let h = host();
        h.state().bindings.insert(42, "account-a-resource".into());
        h.state().names.insert(42, "Account A.sc".into());
        h.refresh(vec![(42, 1, "Account A.sc".into(), false)]);
        assert_eq!(h.snapshot()["documents"][0]["resourceId"], "account-a-resource");
        h.disconnect().unwrap();
        let disconnected = h.snapshot();
        assert!(disconnected["documents"].is_null());
        assert!(disconnected["resources"].as_array().unwrap().is_empty());
        assert!(h.state().bindings.is_empty());
        assert!(h.state().names.is_empty());
        h.connect("test".into(), "Test storage".into(), "account-b".into()).unwrap();
        assert!(h.snapshot()["documents"].is_null());
    }
    #[test]
    fn resource_reads_and_lists_are_scoped_to_current_account_connection() {
        let h = host();
        let connection = h.snapshot()["connectionId"].as_str().unwrap().to_string();
        let rows = vec![Resource { id: "file-1".into(), name: "remote.sc".into(), updated_at: String::new() }];
        assert!(h.set_resources("another-connection", rows.clone()).is_err());
        h.set_resources(&connection, rows).unwrap();
        assert!(h.request_open("unknown").is_err());
        let request = h.request_open("file-1").unwrap();
        assert!(h.open("forged".into(), "remote.sc".into(), vec![1]).is_err());
        h.open(request.clone(), "remote.sc".into(), vec![1]).unwrap();
        assert!(h.open(request.clone(), "remote.sc".into(), vec![1]).is_err());
        assert!(h.cancel_open(request.clone(), String::new()).is_err());
        assert!(h.disconnect().is_err());
        h.take_actions();
        h.finish_open(&request, "file-1", "remote.sc", Err("invalid archive".into()));
        h.disconnect().unwrap();
        let next = h.connect("test".into(), "Test storage".into(), "account-b".into()).unwrap();
        assert_ne!(connection, next);
        assert!(h.set_resources(&connection, Vec::new()).is_err());
        assert!(h.snapshot()["resources"].as_array().unwrap().is_empty());
    }
    #[test]
    fn names_are_native_filenames_and_resource_ids_are_opaque() {
        assert!(valid_native_name("with accents áé.sc"));
        assert!(!valid_native_name("../project.sc"));
        assert!(!valid_native_name("project.svg"));
        assert!(!valid_id("../../project"));
        assert!(!valid_native_name("project.sc\0"));
    }
    #[test]
    fn disabled_provider_does_not_discard_a_capture_already_awaiting_ack() {
        let h = host();
        let (request, uid) = capture(&h, false);
        h.set_enabled(false).unwrap();
        assert!(!h.enabled());
        assert!(h.pending_for(uid));
        h.resolve_dialog(&request, "provider", "in-flight.sc").unwrap();
        h.result(request, "saved".into(), "file-1".into()).unwrap();
        assert!(matches!(h.take_actions().as_slice(),[Action::Save { status,.. }] if status=="saved"));
    }
}
