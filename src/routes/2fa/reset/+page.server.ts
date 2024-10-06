import { recoveryCodeBucket, resetUser2FAWithRecoveryCode } from "$lib/server/2fa";
import { fail, redirect } from "@sveltejs/kit";

import type { Actions, RequestEvent } from "./$types";

export const actions: Actions = {
	default: action
};

export async function load(event: RequestEvent) {
	if (event.locals.session === null || event.locals.user === null) {
		return redirect(302, "/login");
	}
	if (!event.locals.user.emailVerified) {
		return redirect(302, "/verify-email");
	}
	if (!event.locals.user.registered2FA) {
		return redirect(302, "/2fa/setup");
	}
	if (event.locals.session.twoFactorVerified) {
		return redirect(302, "/");
	}
	return {};
}

async function action(event: RequestEvent) {
	if (event.locals.session === null || event.locals.user === null) {
		return fail(401, {
			message: "Not authenticated"
		});
	}
	if (!event.locals.user.emailVerified || !event.locals.user.registered2FA || event.locals.session.twoFactorVerified) {
		return fail(403, {
			message: "Forbidden"
		});
	}
	if (!recoveryCodeBucket.check(event.locals.user.id, 1)) {
		return fail(429, {
			message: "Too many requests"
		});
	}

	const formData = await event.request.formData();
	const code = formData.get("code");
	if (typeof code !== "string") {
		return fail(400, {
			message: "Invalid or missing fields"
		});
	}
	if (code === "") {
		return fail(400, {
			message: "Please enter your code"
		});
	}
	if (!recoveryCodeBucket.consume(event.locals.user.id, 1)) {
		return fail(429, {
			message: "Too many requests"
		});
	}
	const valid = resetUser2FAWithRecoveryCode(event.locals.user.id, code);
	if (!valid) {
		return fail(400, {
			message: "Invalid recovery code"
		});
	}
	recoveryCodeBucket.reset(event.locals.user.id);
	return redirect(302, "/2fa/setup");
}
