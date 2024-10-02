<script lang="ts">
	import { enhance } from "$app/forms";

	import type { ActionData } from "./$types";

	export let form: ActionData;
</script>

<h1>Sign in</h1>
<form method="post" use:enhance>
	<label for="form-login.email">Email</label>
	<input
		type="email"
		id="form-login.email"
		name="email"
		autocomplete="username"
		required
		value={form?.email ?? ""}
	/><br />
	<label for="form-login.password">Password</label>
	<input type="password" id="form-login.password" name="password" autocomplete="current-password" required /><br />
	<button>Continue</button>
	<p>{form?.message ?? ""}</p>
</form>
<a href="/signup">Create an account</a>
<a href="/forgot-password">Forgot password?</a>
