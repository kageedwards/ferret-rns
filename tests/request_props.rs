use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use proptest::prelude::*;

use ferret_rns::link::request::{RequestReceipt, RequestReceiptStatus};

/// Helper: build a RequestReceipt with the given request_id and response data size.
fn make_receipt(request_id: [u8; 16]) -> RequestReceipt {
    let sent_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    RequestReceipt::new(request_id, sent_at, 30.0, 128)
}

// ============================================================================
// Feature: ferret-test-coverage, Property 9: Request response received with callback
// **Validates: Requirements 5.2, 5.4**
// ============================================================================
proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    #[test]
    fn response_received_transitions_to_ready_with_callback(
        request_id in prop::array::uniform16(any::<u8>()),
        response_data in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let mut receipt = make_receipt(request_id);

        // Register a callback that counts invocations
        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&call_count);
        receipt.set_response_callback(Box::new(move |r: &RequestReceipt| {
            counter.fetch_add(1, Ordering::SeqCst);
            // Verify the receipt is in Ready state when callback fires
            assert_eq!(r.get_status(), RequestReceiptStatus::Ready);
        }));

        // Call response_received
        let data_clone = response_data.clone();
        receipt.response_received(response_data);

        // Status should be Ready
        prop_assert_eq!(receipt.get_status(), RequestReceiptStatus::Ready);

        // Response data should be stored
        prop_assert_eq!(receipt.get_response(), Some(data_clone.as_slice()));

        // response_concluded_at should be set
        prop_assert!(receipt.response_concluded_at.is_some(), "response_concluded_at should be set");

        // Callback should have been invoked exactly once
        prop_assert_eq!(call_count.load(Ordering::SeqCst), 1, "response callback should be invoked exactly once");
    }
}

// ============================================================================
// Unit tests for RequestReceipt initial state and timeout with callback
// Requirements: 5.1, 5.3, 5.5
// ============================================================================

#[test]
fn initial_state_is_sent_with_valid_request_id_and_sent_at() {
    let request_id = [0xAB_u8; 16];
    let receipt = make_receipt(request_id);

    // Status should be Sent
    assert_eq!(receipt.get_status(), RequestReceiptStatus::Sent);

    // request_id should be the 16-byte value we provided
    assert_eq!(receipt.request_id.len(), 16);
    assert_eq!(receipt.request_id, request_id);

    // sent_at should be a reasonable timestamp (> 0)
    assert!(receipt.sent_at > 0.0, "sent_at should be a positive timestamp");

    // No response yet
    assert!(receipt.get_response().is_none());
    assert!(receipt.concluded_at.is_none());
    assert!(receipt.response_concluded_at.is_none());
}

#[test]
fn request_timed_out_transitions_to_failed_with_callback() {
    let request_id = [0xCD_u8; 16];
    let mut receipt = make_receipt(request_id);

    // Register a failed callback that counts invocations
    let call_count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&call_count);
    receipt.set_failed_callback(Box::new(move |r: &RequestReceipt| {
        counter.fetch_add(1, Ordering::SeqCst);
        // Verify the receipt is in Failed state when callback fires
        assert_eq!(r.get_status(), RequestReceiptStatus::Failed);
    }));

    // Trigger timeout
    receipt.request_timed_out();

    // Status should be Failed
    assert_eq!(receipt.get_status(), RequestReceiptStatus::Failed);

    // concluded_at should be set
    assert!(
        receipt.concluded_at.is_some(),
        "concluded_at should be set after timeout"
    );

    // Callback should have been invoked exactly once
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        1,
        "failed callback should be invoked exactly once"
    );
}
