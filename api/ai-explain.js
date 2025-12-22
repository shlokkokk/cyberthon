export default async function handler(req, res) {
    if (req.method !== "POST") {
        return res.status(405).json({ error: "Method not allowed" });
    }

    try {
        const { summary } = req.body;

        if (!summary) {
            return res.status(400).json({
                explanation: "No analysis summary provided."
            });
        }

        const response = await fetch(
            "https://api.openai.com/v1/chat/completions",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${process.env.OPENAI_API_KEY}`
                },
                body: JSON.stringify({
                    model: "gpt-4o-mini",
                    temperature: 0.4,
                    messages: [
                        {
                            role: "system",
                            content:
                                "You are a cybersecurity analyst AI. Explain malware risks clearly, briefly, and in simple language for non-technical users."
                        },
                        {
                            role: "user",
                            content: summary
                        }
                    ]
                })
            }
        );

        const data = await response.json();

        const explanation =
            data.choices?.[0]?.message?.content ||
            "AI could not generate an explanation.";

        return res.status(200).json({ explanation });

    } catch (err) {
        return res.status(500).json({
            explanation:
                "AI explanation unavailable. Showing heuristic-based analysis only."
        });
    }
}

