use crate::{
    error::OAuthTSLError,
    managers::status_provider::StatusProvider,
    status_list::{IndexInput, StatusList},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusIssuer {
    pub meta_status_lists: HashMap<String, MetaStatusList>,
}

impl Default for StatusIssuer {
    fn default() -> Self {
        Self::new()
    }
}

impl StatusIssuer {
    pub fn new() -> Self {
        Self {
            meta_status_lists: HashMap::new(),
        }
    }

    /// Creates a `StatusProvider`, converting all the issuer's status lists to Status List Tokens.
    pub fn create_status_provider(&self) -> Result<StatusProvider, OAuthTSLError> {
        let mut status_list_tokens = HashMap::new();

        for (key, status_list) in &self.meta_status_lists {
            status_list_tokens.insert(key.clone(), status_list.status_list.compress_encode()?);
        }

        Ok(StatusProvider { status_list_tokens })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaStatusList {
    used_indices: Vec<usize>,
    pub status_list: StatusList,
}

impl MetaStatusList {
    pub fn get_index(&self, index: usize) -> Result<u8, OAuthTSLError> {
        self.status_list.get_index(index)
    }

    /// Sets the status at the specified index to the given value.
    /// Always enlarges the status list to the required size if it is not already large enough.
    /// Therefore an index can never be out of bounds, also stores the index for the issuer to know what index is used.
    pub fn set_index(&mut self, index: usize, value: u8) -> Result<(), OAuthTSLError> {
        self.status_list.set_index(index, value)?;
        if !self.used_indices.contains(&index) {
            self.used_indices.push(index);
        }

        Ok(())
    }

    /// Uses an enum to allow single or multiple input values, enabling setting all indices to one value or setting a value per index.
    pub fn set_index_array(
        &mut self,
        indices: Vec<usize>,
        index_input: IndexInput,
    ) -> Result<(), OAuthTSLError> {
        self.status_list
            .set_index_array(indices.clone(), index_input)?;
        for index in indices {
            if !self.used_indices.contains(&index) {
                self.used_indices.push(index);
            }
        }

        Ok(())
    }
}
