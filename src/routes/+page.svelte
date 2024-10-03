<script lang="ts">
	import { enhance } from "$app/forms";

	import type { PageData } from "./$types";

	export let data: PageData;
</script>

<h1>Hi {data.user.username}!</h1>
<form method="post" use:enhance>
	<button>Sign out</button>
</form>
