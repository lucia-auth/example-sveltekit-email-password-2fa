<script lang="ts">
	import { enhance } from "$app/forms";

	import type { PageData, ActionData } from "./$types";

	export let data: PageData;
	export let form: ActionData;
</script>

<header>
	<a href="/">Home</a>
	<a href="/settings">Settings</a>
</header>
<main>
	<h1>Settings</h1>
	<section>
		<h2>Update email</h2>
		<p>Your email: {data.user.email}</p>
		<form method="post" use:enhance action="?/email">
			<label for="form-email.email">New email</label>
			<input type="email" id="form-email.email" name="email" required /><br />
			<button>Update</button>
			<p>{form?.email?.message ?? ""}</p>
		</form>
	</section>
	<section>
		<h2>Update password</h2>
		<form method="post" use:enhance action="?/password">
			<label for="form-password.password">Current password</label>
			<input type="password" id="form-email.password" name="password" autocomplete="current-password" required /><br />
			<label for="form-password.new-password">New password</label>
			<input
				type="password"
				id="form-password.new-password"
				name="new_password"
				autocomplete="new-password"
				required
			/><br />
			<button>Update</button>
			<p>{form?.password?.message ?? ""}</p>
		</form>
	</section>
	{#if data.user.registered2FA}
		<section>
			<h2>Update two-factor authentication</h2>
			<a href="/2fa/setup">Update</a>
		</section>
	{/if}
	{#if data.recoveryCode !== null}
		<section>
			<h1>Recovery code</h1>
			<p>Your recovery code is: {data.recoveryCode}</p>
			<button>Generate new code</button>
		</section>
	{/if}
</main>
