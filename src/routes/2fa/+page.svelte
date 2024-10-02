<script lang="ts">
	import { enhance } from "$app/forms";

	import type { ActionData } from "./$types";

	export let form: ActionData;
</script>

<h1>Two-factor authentication</h1>
<form method="post" use:enhance>
	<label for="form-totp.code">Enter the code from your app</label>
	<input id="form-totp.code" name="code" autocomplete="one-time-code" required /><br />
	<button>Verify</button>
	<p>{form?.message ?? ""}</p>
</form>
<a href="/2fa/reset">Use recovery code</a>
