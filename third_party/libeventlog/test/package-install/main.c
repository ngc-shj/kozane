#include <stdio.h>
#include <string.h>

#include "event_record.h"
#include "tcg.h"

int main(void)
{
	static uint8_t event_log[0x400];
	const char payload[] = "hello event log";

	tpm_alg_id algos[] = {
		EVLOG_TPM_ALG_SHA256,
	};

	if (event_log_init(event_log, event_log + sizeof(event_log)) != 0) {
		return 1;
	}

	if (event_log_write_header(algos, 1, 0U, NULL, 0U) != 0) {
		return 1;
	}

	if (event_log_write_pcr_event2_single(0, EV_ACTION, SHA256_DIGEST_SIZE,
					      NULL, (const uint8_t *)payload,
					      (uint32_t)sizeof(payload)) != 0) {
		return 1;
	}

	printf("event log size: %zu bytes\n",
	       event_log_get_cur_size(event_log));
	return 0;
}
