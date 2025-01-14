// Copyright 2023 Naian G.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use axum::{extract::State, Json};
use log::{debug, info};

use crate::{didcomm_types::ForwardMsg, storage::MediatorPersistence};

pub async fn handle_forward<T>(
    State(storage): State<Arc<T>>,
    Json(forward_msg): Json<ForwardMsg>,
) -> Json<ForwardMsg>
where
    T: MediatorPersistence,
{
    info!("Persisting forward message");
    debug!("{forward_msg:#?}");
    let _ = storage
        .persist_forward_message(&forward_msg.recipient_key, &forward_msg.message_data)
        .await;
    Json(forward_msg)
}
