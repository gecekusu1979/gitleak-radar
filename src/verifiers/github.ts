export async function verifyGithubPat(token: string): Promise<boolean | null> {
    try {
        const res = await fetch("https://api.github.com/user", {
            headers: {
                Authorization: `Bearer ${token}`,
                "User-Agent": "gitleak-radar-verifier"
            }
        });

        if (res.status === 200) return true;
        if (res.status === 401 || res.status === 403) return false;

        // Rate limits or other errors mean we are unsure
        return null;
    } catch (err: any) {
        return null;
    }
}
