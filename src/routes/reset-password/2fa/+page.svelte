<script lang="ts">
	import { enhance } from "$app/forms";

	import type { ActionData } from "./$types";

	export let form: ActionData;
</script>

<h1>Two-factor authentication</h1>
<p>Enter the code from your authenticator app.</p>
<form method="post" use:enhance action="?/totp">
	<label for="form-totp.code">Code</label>
	<input id="form-totp.code" name="code" required /><br />
	<button>Verify</button>
	<p>{form?.totp?.message ?? ""}</p>
</form>
<section>
	<h2>Use your recovery code instead</h2>
	<form method="post" use:enhance action="?/recovery_code">
		<label for="form-recovery-code.code">Recovery code</label>
		<input id="form-recovery-code.code" name="code" required /><br />
		<button>Verify</button>
		<p>{form?.recoveryCode?.message ?? ""}</p>
	</form>
</section>
