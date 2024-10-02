<script lang="ts">
	import { enhance } from "$app/forms";

	import type { ActionData } from "./$types";

	export let form: ActionData;
</script>

<h1>Recover your account</h1>
<form method="post" use:enhance>
	<label for="form-totp.code">Recovery code</label>
	<input id="form-totp.code" name="code" required /><br />
	<button>Verify</button>
	<p>{form?.message ?? ""}</p>
</form>
