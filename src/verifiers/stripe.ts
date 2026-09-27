export async function verifyStripeKey(token: string): Promise<boolean | null> {
    try {
        const res = await fetch("https://api.stripe.com/v1/charges", {
            headers: {
                Authorization: `Bearer ${token}`
            }
        });

        if (res.status === 200) return true; // valid
        if (res.status === 401) {
            // "Invalid API Key" returns 401
            return false;
        }
        // If it returns 403, it might mean valid key but no permissions, which means active.
        if (res.status === 403) return true;

        return null;
    } catch (err: any) {
        return null;
    }
}
