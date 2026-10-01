export class TrieNode {
    public children = new Map<string, TrieNode>();
    public fail: TrieNode | null = null;
    public outputs: Set<string> = new Set();
}

/**
 * A highly optimized, zero-dependency Aho-Corasick automaton implementation
 * tailored for multi-pattern keyword scaling in JS/TS applications.
 */
export class AhoCorasick {
    private root = new TrieNode();
    private isCompiled = false;

    /**
     * Initialize a new automaton with an array of keywords.
     */
    constructor(keywords: string[]) {
        for (const keyword of keywords) {
            if (keyword.length === 0) continue;
            this.insert(keyword.toLowerCase());
        }
        this.buildFailureLinks();
        this.isCompiled = true;
    }

    private insert(word: string): void {
        let current = this.root;
        for (const char of word) {
            if (!current.children.has(char)) {
                current.children.set(char, new TrieNode());
            }
            current = current.children.get(char)!;
        }
        current.outputs.add(word);
    }

    private buildFailureLinks(): void {
        const queue: TrieNode[] = [];

        // Initialize root's children
        for (const child of this.root.children.values()) {
            child.fail = this.root;
            queue.push(child);
        }

        while (queue.length > 0) {
            const current = queue.shift()!;

            for (const [char, child] of current.children.entries()) {
                queue.push(child);
                let failNode = current.fail;

                // Traverse failure links to find longest strict suffix
                while (failNode !== null && !failNode.children.has(char)) {
                    failNode = failNode.fail;
                }

                child.fail = failNode ? failNode.children.get(char)! : this.root;

                // Merge outputs of the failNode to catch overlapping patterns
                if (child.fail.outputs.size > 0) {
                    for (const output of child.fail.outputs) {
                        child.outputs.add(output);
                    }
                }
            }
        }
    }

    /**
     * Search input text and return a set of matched keywords.
     * Runs in O(n + m) time complexity.
     */
    public search(text: string): string[] {
        if (!this.isCompiled) throw new Error("AhoCorasick not compiled correctly.");

        const results = new Set<string>();
        let current = this.root;

        for (let i = 0; i < text.length; i++) {
            const char = text[i] as string;

            // Follow failure links back to root if path broken
            while (current !== this.root && !current.children.has(char)) {
                current = current.fail!;
            }

            current = current.children.get(char) || this.root;

            // If outputs exist at node, we matched substrings
            if (current.outputs.size > 0) {
                for (const out of current.outputs) {
                    results.add(out);
                }
            }
        }

        return Array.from(results);
    }
}
