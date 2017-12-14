COMP116 Final Project -- Supporting Material
===========================================

I have obtained the source code for two versions of `wpa_supplicant`, the
open-source implementation of WPA2 found in most Linux distributions including
Android phones. One version is patched to protect against KRACK attacks while
the other is not. I compared code from the two versions of `wpa_supplicant` to
identify exactly where and how the vulnerability was fixed, and I will be
analyzing the code added to the patched version of the software. (Source was
downloaded from the Debian GNU/Linux software repository. Packages downloaded
were `wpa_2.4-1` and `wpa_2.4-1+9u1`.)

The patch involves just a few lines of code in a file called wpa.c. The
function in question is called `wpa_supplicant_install_gtk()` which makes
sense since the exploit takes advantage of the third handshake of WPA2 which
generates and installs the Group Temporal Key. The relevant code is reproduced
below. The added block of code seems to be a kind of sanity check. Before
further analysis, I will outline the arguments passed to the function to
provide a better understanding of the context of the function. The arguments
are as follows:

* `struct wpa_sm *sm` -- This is a pointer to a struct describing the
		WPA state machine
* `const struct wpa_gtk_data *gd` -- This is a pointer to a struct containing
	data for the GTK
* `const u8 *key_rsc` -- This is a pointer to an unsigned 8-bit integer
	containing the key's Receive Sequence Counter
* `int wnm_sleep` -- is an integer that keeps track of the Wireless Network
	Management Sleep Mode Response frame

The patch compares the GTK in the WPA state machine with the one passed to the
function from previous steps in the four-way handshake and the `wnm_sleep`
counter from the state machine to the counter contained in the `gtk_data`
struct and to the counter passed directly to the function. If any of these
items are equal, the function prints a debug message, returns 0, and does not
install (re-install) the key. It seems that the key stored in the state machine
has a longer life than the one passed to the function which likely changes
each time a handshake is initiated (unless a KRACK attack is being attempted).
Essentially, this detects if someone tries to re-authenticate an already in-use
key and prevents the encryption key from being reset.

Code
----
```
static int wpa_supplicant_install_gtk(struct wpa_sm *sm,
				      const struct wpa_gtk_data *gd,
				      const u8 *key_rsc, int wnm_sleep)
{
	const u8 *_gtk = gd->gtk;
	u8 gtk_buf[32];

	/* Detect possible key reinstallation */
	if ((sm->gtk.gtk_len == (size_t) gd->gtk_len &&
	     os_memcmp(sm->gtk.gtk, gd->gtk, sm->gtk.gtk_len) == 0) ||
	    (sm->gtk_wnm_sleep.gtk_len == (size_t) gd->gtk_len &&
	     os_memcmp(sm->gtk_wnm_sleep.gtk, gd->gtk,
		       sm->gtk_wnm_sleep.gtk_len) == 0)) {
		wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
			"WPA: Not reinstalling already in-use GTK to the driver (keyidx=%d tx=%d len=%d)",
			gd->keyidx, gd->tx, gd->gtk_len);
		return 0;
	}
 /* After this if block the code is identical to the version that predates KRACK. */
}
```

	--Adon Shapiro
