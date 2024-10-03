<script lang="ts">
	import { enhance } from "$app/forms";

	import type { ActionData, PageData } from "./$types";

	export let data: PageData;
	export let form: ActionData;
</script>

<h1>Verify your email address</h1>
<p>We sent an 8-digit code to {data.email}.</p>
<form method="post" use:enhance action="?/verify">
	<label for="form-verify.code">Code</label>
	<input id="form-verify.code" name="code" required />
	<button>Verify</button>
	<p>{form?.verify?.message ?? ""}</p>
</form>
<form method="post" use:enhance action="?/resend">
	<button>Resend code</button>
	<p>{form?.resend?.message ?? ""}</p>
</form>
<a href="/settings">Change your email</a>
