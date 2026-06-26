use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Standalone convenience functions
// ---------------------------------------------------------------------------

/// Verify a capability token (basic: resource + operation only).
/// Throws on failure.
#[wasm_bindgen]
pub fn verify_capability(
    token: &str,
    public_key: &str,
    resource: &str,
    operation: &str,
) -> Result<(), JsError> {
    let pk = parse_key(public_key)?;
    hessra_cap_token::CapabilityVerifier::new(
        token.to_string(),
        pk,
        resource.to_string(),
        operation.to_string(),
    )
    .verify()
    .map_err(to_js_error)
}

/// Verify a capability token with subject binding.
/// Throws on failure.
#[wasm_bindgen]
pub fn verify_capability_with_subject(
    token: &str,
    public_key: &str,
    resource: &str,
    operation: &str,
    subject: &str,
) -> Result<(), JsError> {
    let pk = parse_key(public_key)?;
    hessra_cap_token::CapabilityVerifier::new(
        token.to_string(),
        pk,
        resource.to_string(),
        operation.to_string(),
    )
    .with_subject(subject.to_string())
    .verify()
    .map_err(to_js_error)
}

/// Verify a capability token with designation checks.
/// `designations` is a JS array of `{ label: string, value: string }` objects.
/// Throws on failure.
#[wasm_bindgen]
pub fn verify_designated_capability(
    token: &str,
    public_key: &str,
    resource: &str,
    operation: &str,
    designations: js_sys::Array,
) -> Result<(), JsError> {
    let pk = parse_key(public_key)?;
    let mut verifier = hessra_cap_token::CapabilityVerifier::new(
        token.to_string(),
        pk,
        resource.to_string(),
        operation.to_string(),
    );

    for item in designations.iter() {
        let label = js_sys::Reflect::get(&item, &"label".into())
            .map_err(|_| JsError::new("Designation missing 'label' field"))?
            .as_string()
            .ok_or_else(|| JsError::new("Designation 'label' must be a string"))?;
        let value = js_sys::Reflect::get(&item, &"value".into())
            .map_err(|_| JsError::new("Designation missing 'value' field"))?
            .as_string()
            .ok_or_else(|| JsError::new("Designation 'value' must be a string"))?;
        verifier = verifier.with_designation(label, value);
    }

    verifier.verify().map_err(to_js_error)
}

/// Get the hex-encoded revocation ID of a capability token's authority block.
#[wasm_bindgen]
pub fn get_revocation_id(token: &str, public_key: &str) -> Result<String, JsError> {
    let pk = parse_key(public_key)?;
    let rev_id = hessra_cap_token::get_capability_revocation_id(token.to_string(), pk)
        .map_err(to_js_error)?;
    Ok(rev_id.to_hex())
}

/// Validate a public key string format. Throws on invalid.
#[wasm_bindgen]
pub fn parse_public_key(key: &str) -> Result<(), JsError> {
    parse_key(key)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// CapabilityVerifier class (builder pattern)
// ---------------------------------------------------------------------------

/// Builder for verifying Hessra capability tokens.
///
/// Mirrors the Rust `CapabilityVerifier` API.
///
/// ```typescript
/// new CapabilityVerifier(token, publicKey, "tool:web-fetch", "invoke")
///   .with_designation("path", "src/main.rs")
///   .verify(); // throws on failure
/// ```
#[wasm_bindgen(js_name = "CapabilityVerifier")]
pub struct WasmCapabilityVerifier {
    token: String,
    public_key: hessra_token_core::PublicKey,
    resource: String,
    operation: String,
    subject: Option<String>,
    designations: Vec<(String, String)>,
}

#[wasm_bindgen(js_class = "CapabilityVerifier")]
impl WasmCapabilityVerifier {
    #[wasm_bindgen(constructor)]
    pub fn new(
        token: &str,
        public_key: &str,
        resource: &str,
        operation: &str,
    ) -> Result<WasmCapabilityVerifier, JsError> {
        let pk = parse_key(public_key)?;
        Ok(Self {
            token: token.to_string(),
            public_key: pk,
            resource: resource.to_string(),
            operation: operation.to_string(),
            subject: None,
            designations: Vec::new(),
        })
    }

    #[wasm_bindgen]
    pub fn with_subject(mut self, subject: &str) -> Self {
        self.subject = Some(subject.to_string());
        self
    }

    #[wasm_bindgen]
    pub fn with_designation(mut self, label: &str, value: &str) -> Self {
        self.designations
            .push((label.to_string(), value.to_string()));
        self
    }

    #[wasm_bindgen]
    pub fn verify(self) -> Result<(), JsError> {
        let mut verifier = hessra_cap_token::CapabilityVerifier::new(
            self.token,
            self.public_key,
            self.resource,
            self.operation,
        );

        if let Some(subject) = self.subject {
            verifier = verifier.with_subject(subject);
        }
        for (label, value) in self.designations {
            verifier = verifier.with_designation(label, value);
        }

        verifier.verify().map_err(to_js_error)
    }
}

// ---------------------------------------------------------------------------
// DesignationBuilder class
// ---------------------------------------------------------------------------

/// Builder for attenuating capability tokens with designation blocks.
///
/// Narrows an existing token's scope using public key only (no signing key needed).
///
/// ```typescript
/// const narrowed = DesignationBuilder.from_base64(token, publicKey)
///   .designate("tenant_id", "acme-corp")
///   .designate("user", "alice")
///   .attenuate(); // returns new base64 token
/// ```
#[wasm_bindgen(js_name = "DesignationBuilder")]
pub struct WasmDesignationBuilder {
    inner: Option<hessra_cap_token::CapabilityAmendment>,
}

#[wasm_bindgen(js_class = "DesignationBuilder")]
impl WasmDesignationBuilder {
    /// Create a DesignationBuilder from a base64-encoded token.
    #[wasm_bindgen]
    pub fn from_base64(token: &str, public_key: &str) -> Result<WasmDesignationBuilder, JsError> {
        let pk = parse_key(public_key)?;
        let builder = hessra_cap_token::HessraCapability::amend(token, pk).map_err(to_js_error)?;
        Ok(Self {
            inner: Some(builder),
        })
    }

    /// Add a designation (label, value) pair to narrow the token's scope.
    #[wasm_bindgen]
    pub fn designate(
        mut self,
        label: &str,
        value: &str,
    ) -> Result<WasmDesignationBuilder, JsError> {
        let builder = self
            .inner
            .take()
            .ok_or_else(|| JsError::new("DesignationBuilder already consumed"))?;
        Ok(Self {
            inner: Some(builder.designation(label, value)),
        })
    }

    /// Attenuate the token with all accumulated designations.
    /// Returns the attenuated token as a base64 string.
    #[wasm_bindgen]
    pub fn attenuate(mut self) -> Result<String, JsError> {
        let builder = self
            .inner
            .take()
            .ok_or_else(|| JsError::new("DesignationBuilder already consumed"))?;
        builder.attenuate().map_err(to_js_error)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn parse_key(key: &str) -> Result<hessra_token_core::PublicKey, JsError> {
    hessra_cap_token::biscuit_key_from_string(key.to_string()).map_err(to_js_error)
}

fn to_js_error(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}
