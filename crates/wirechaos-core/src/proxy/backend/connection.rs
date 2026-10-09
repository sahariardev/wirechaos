use std::collections::HashMap;

#[derive(Default)]
pub struct Backend {
    parameters_status_values: HashMap<String, String>,
}

impl Backend {
    pub fn get_param_status_values(&self) -> Vec<(String, String)> {
        let mut params: Vec<(String, String)> = Vec::new();

        for (key, value) in &self.parameters_status_values {
            params.push((key.to_owned(), value.to_owned()));
        }

        params
    }
}
