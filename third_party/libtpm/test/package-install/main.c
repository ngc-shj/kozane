#include <stddef.h>

#include <tpm2/spi.h>
#include <tpm2/tpm2.h>

const struct tpm_spi_plat *tpm_spidev;

int main(void)
{
	// Just reference a couple of symbols to ensure linking works
	// (Adjust these function names to real ones from your library)
	tpm_interface_init(NULL, NULL, NULL, 0);
	tpm_startup(NULL, 0);
	return 0;
}
