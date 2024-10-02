<script lang="ts">
	import { enhance } from "$app/forms";

	import type { ActionData, PageData } from "./$types";

	export let data: PageData;
	export let form: ActionData;
</script>

<h1>Set up two-factor authentication</h1>
<div style="width:200px; height: 200px;">
	{@html data.qrcode}
</div>
<form method="post" use:enhance>
	<input name="key" value={data.encodedTOTPKey} hidden required />
	<label for="form-totp.code">Verify the code from the app</label>
	<input id="form-totp.code" name="code" required /><br />
	<button>Save</button>
	<p>{form?.message ?? ""}</p>
</form>
