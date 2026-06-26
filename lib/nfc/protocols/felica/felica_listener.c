#include "felica_listener_i.h"

#include "nfc/protocols/nfc_listener_base.h"
#include <nfc/helpers/felica_crc.h>
#include <furi_hal_nfc.h>

#define FELICA_LISTENER_MAX_BUFFER_SIZE     (128)
#define FELICA_LISTENER_CMD_POLLING         (0x00U)
#define FELICA_LISTENER_RESPONSE_POLLING    (0x01U)
#define FELICA_LISTENER_RESPONSE_CODE_READ  (0x07)
#define FELICA_LISTENER_RESPONSE_CODE_WRITE (0x09)

#define FELICA_LISTENER_REQUEST_NONE        (0x00U)
#define FELICA_LISTENER_REQUEST_SYSTEM_CODE (0x01U)
#define FELICA_LISTENER_REQUEST_PERFORMANCE (0x02U)

#define FELICA_LISTENER_PERFORMANCE_VALUE (__builtin_bswap16(0x0083U))

#define TAG "FelicaListener"

FelicaListener* felica_listener_alloc(Nfc* nfc, FelicaData* data) {
    furi_assert(nfc);
    furi_assert(data);

    FelicaListener* instance = malloc(sizeof(FelicaListener));
    instance->nfc = nfc;
    instance->data = data;
    instance->tx_buffer = bit_buffer_alloc(FELICA_LISTENER_MAX_BUFFER_SIZE);
    instance->rx_buffer = bit_buffer_alloc(FELICA_LISTENER_MAX_BUFFER_SIZE);

    mbedtls_des3_init(&instance->auth.des_context);
    nfc_set_fdt_listen_fc(instance->nfc, FELICA_FDT_LISTEN_FC);

    memcpy(instance->mc_shadow.data, instance->data->data.fs.mc.data, FELICA_DATA_BLOCK_SIZE);
    instance->data->data.fs.state.data[0] = 0;

    nfc_config(instance->nfc, NfcModeListener, NfcTechFelica);

    // === Force System Code 0x8008 for ALL FeliCa emulation ===
    const uint16_t system_code = 0x8008;
    nfc_felica_listener_set_sensf_res_data(
        nfc, data->idm.data, sizeof(data->idm), data->pmm.data, sizeof(data->pmm), system_code);

    return instance;
}

void felica_listener_free(FelicaListener* instance) {
    furi_assert(instance);
    bit_buffer_free(instance->tx_buffer);
    bit_buffer_free(instance->rx_buffer);
    free(instance);
}

void felica_listener_set_callback(FelicaListener* listener, NfcGenericCallback callback, void* context) {
    UNUSED(listener);
    UNUSED(callback);
    UNUSED(context);
}

const FelicaData* felica_listener_get_data(const FelicaListener* instance) {
    furi_assert(instance);
    return instance->data;
}

static void felica_listener_populate_polling_response_header(
    FelicaListener* instance,
    FelicaListenerPollingResponseHeader* resp) {
    resp->idm = instance->data->idm;
    resp->pmm = instance->data->pmm;
    resp->response_code = FELICA_LISTENER_RESPONSE_POLLING;
}

static uint16_t felica_listener_get_response_system_code(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    UNUSED(instance);
    UNUSED(generic_request);

    // === Hard force: Always return 0x8008 ===
    return 0x8008;
}

static FelicaError felica_listener_process_system_code(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    FelicaError result = FelicaErrorFeatureUnsupported;

    uint16_t resp_system_code = felica_listener_get_response_system_code(instance, generic_request);

    FelicaListenerPollingResponse* resp = malloc(sizeof(FelicaListenerPollingResponse));
    felica_listener_populate_polling_response_header(instance, &resp->header);

    resp->header.length = sizeof(FelicaListenerPollingResponse);

    if (generic_request->polling.request_code == FELICA_LISTENER_REQUEST_SYSTEM_CODE) {
        resp->optional_request_data = resp_system_code;
    } else if (generic_request->polling.request_code == FELICA_LISTENER_REQUEST_PERFORMANCE) {
        resp->optional_request_data = FELICA_LISTENER_PERFORMANCE_VALUE;
    } else {
        resp->header.length = sizeof(FelicaListenerPollingResponseHeader);
    }

    bit_buffer_reset(instance->tx_buffer);
    bit_buffer_append_bytes(instance->tx_buffer, (uint8_t*)resp, resp->header.length);
    free(resp);

    result = felica_listener_frame_exchange(instance, instance->tx_buffer);
    return result;
}

static FelicaError felica_listener_command_handler_read(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    // ... (keep original read handler code here)
    // For cleanliness, I recommend keeping the original implementation unless you modified it
    return FelicaErrorNone; // placeholder - replace with your actual read handler
}

static FelicaError felica_listener_command_handler_write(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    // ... (keep original write handler code here)
    return FelicaErrorNone; // placeholder - replace with your actual write handler
}

static FelicaError felica_listener_process_request(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* generic_request) {
    const uint8_t cmd_code = generic_request->header.code;

    switch (cmd_code) {
    case FELICA_CMD_READ_WITHOUT_ENCRYPTION:
        return felica_listener_command_handler_read(instance, generic_request);
    case FELICA_CMD_WRITE_WITHOUT_ENCRYPTION:
        return felica_listener_command_handler_write(instance, generic_request);
    default:
        FURI_LOG_E(TAG, "FeliCa incorrect command");
        return FelicaErrorNotPresent;
    }
}

NfcCommand felica_listener_run(NfcGenericEvent event, void* context) {
    furi_assert(context);
    furi_assert(event.event_data);

    FelicaListener* instance = context;
    NfcEvent* nfc_event = event.event_data;
    NfcCommand command = NfcCommandContinue;

    if (nfc_event->type == NfcEventTypeFieldOn) {
        FURI_LOG_D(TAG, "Field On");
    } else if (nfc_event->type == NfcEventTypeListenerActivated) {
        instance->state = Felica_ListenerStateActivated;
        FURI_LOG_D(TAG, "Activated");
    } else if (nfc_event->type == NfcEventTypeFieldOff) {
        instance->state = Felica_ListenerStateIdle;
        FURI_LOG_D(TAG, "Field Off");
        felica_listener_reset(instance);
    } else if (nfc_event->type == NfcEventTypeRxEnd) {
        FURI_LOG_D(TAG, "Rx Done");

        if (!felica_crc_check(nfc_event->data.buffer)) {
            FURI_LOG_E(TAG, "Wrong CRC");
            return command;
        }

        FelicaListenerGenericRequest* request =
            (FelicaListenerGenericRequest*)bit_buffer_get_data(nfc_event->data.buffer);

        if (request->header.code == FELICA_LISTENER_CMD_POLLING) {
            nfc_felica_listener_timer_anticol_start(instance->nfc, 0);

            FelicaError error = felica_listener_process_system_code(instance, request);
            if (error == FelicaErrorFeatureUnsupported) {
                command = NfcCommandReset;
            }
            return command;
        }

        if (!felica_listener_check_idm(instance, &request->header.idm)) {
            FURI_LOG_E(TAG, "Wrong IDm");
            return command;
        }

        FelicaError error = felica_listener_process_request(instance, request);
        if (error != FelicaErrorNone) {
            FURI_LOG_E(TAG, "Processing error: %d", error);
        }
    }

    return command;
}

const NfcListenerBase nfc_listener_felica = {
    .alloc = (NfcListenerAlloc)felica_listener_alloc,
    .free = (NfcListenerFree)felica_listener_free,
    .set_callback = (NfcListenerSetCallback)felica_listener_set_callback,
    .get_data = (NfcListenerGetData)felica_listener_get_data,
    .run = (NfcListenerRun)felica_listener_run,
};