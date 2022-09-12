use core_lib::model::document::EncryptedDocument;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentBucket {
    pub count: u64,
    pub pid: String,
    pub docs: Vec<EncryptedDocument>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentBucketUpdate {
    pub id: String,
    pub dt_id: String,
    pub ts: i64,
    pub tc: i64,
    pub hash: String,
    pub keys_ct: String,
    pub cts: Vec<String>
}

impl DocumentBucket{
    pub fn new(pid: String, docs: Vec<EncryptedDocument>) -> DocumentBucket {
        DocumentBucket{
            count: docs.len() as u64,
            pid,
            docs,
        }
    }

    pub fn add(mut self, mut doc: EncryptedDocument){
        // only add document if pid is correct
        if self.pid == doc.pid{
            // null doc pid
            self.docs.push(doc);
            self.count = self.count + 1
        }
    }
}
