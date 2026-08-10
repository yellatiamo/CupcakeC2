//! DCSync op — default feature-off (KD-18). Lab builds enable `ad-dcsync`.

use crate::{AdJobRequest, AdJobResponse};

pub fn handle_dcsync(req: &AdJobRequest) -> AdJobResponse {
    #[cfg(not(feature = "ad-dcsync"))]
    {
        return AdJobResponse {
            request_id: req.request_id.clone(),
            status: "error".into(),
            stdout: String::new(),
            stderr: "dcsync requires ad-dcsync feature (default off)".into(),
            error_code: "feature_disabled".into(),
        };
    }

    #[cfg(feature = "ad-dcsync")]
    {
        use crate::domain::{probe_domain, require_domain};
        use serde_json::json;
        match require_domain(&req.request_id, probe_domain()) {
            Err(e) => e,
            Ok((domain, dcs)) => {
                // Lab stub: no full DRSUAPI yet — access_denied rather than fake hashes.
                AdJobResponse {
                    request_id: req.request_id.clone(),
                    status: "error".into(),
                    stdout: json!({
                        "domain": domain,
                        "dc": dcs.first(),
                        "note": "drsuapi_stub"
                    })
                    .to_string(),
                    stderr: "access_denied".into(),
                    error_code: "access_denied".into(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn default_build_feature_disabled() {
        let req = AdJobRequest {
            request_id: "d1".into(),
            op: "dcsync".into(),
            params: Value::Null,
            deadline_ms: 1000,
        };
        let resp = handle_dcsync(&req);
        #[cfg(not(feature = "ad-dcsync"))]
        {
            assert_eq!(resp.error_code, "feature_disabled");
        }
        #[cfg(feature = "ad-dcsync")]
        {
            // With feature, may be access_denied or domain soft code
            assert_ne!(resp.error_code, "not_implemented");
        }
    }
}
