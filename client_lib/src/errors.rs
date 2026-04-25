use std::error::Error;

use wasm_bindgen::JsValue;

#[derive(Debug)]
/// Wrapper struct for converting Rust errors into JavaScript errors.
///
/// This struct implements `Into<JsValue>` to allow seamless error propagation to JavaScript environments in Wasm.
pub struct JsError(Box<dyn Error>);

impl From<Box<dyn Error>> for JsError {
    fn from(err: Box<dyn Error>) -> Self {
        JsError(err)
    }
}

impl Into<JsValue> for JsError {
    fn into(self) -> JsValue {
        JsValue::from_str(&self.0.to_string())
    }
}
