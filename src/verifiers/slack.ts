export async function verifySlackWebhook(url: string): Promise<boolean | null> {
    try {
        // A GET or empty POST to a valid Slack webhook returns 400 "invalid_payload" or 400 "No text specified"
        // An invalid/revoked Webhook returns commonly 404 or 403.
        const res = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({}),
            signal: AbortSignal.timeout(5000)
        });

        const text = await res.text();
        // If we get an explicit text payload error but not a 404, the webhook exists.
        if (res.status === 400 && text.includes("invalid_payload")) return true;
        if (text.includes("no_text")) return true;

        if (res.status === 404 || res.status === 403) return false;

        return null;
    } catch (err: any) {
        return null;
    }
}
