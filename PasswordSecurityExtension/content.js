// ============================================================
// Password Security Checker
// ============================================================

const passwordFields = new WeakMap();


// ============================================================
// Find password fields
// ============================================================

function findPasswordFields() {

    const fields = document.querySelectorAll(
        'input[type="password"]'
    );

    fields.forEach(field => {

        if (!passwordFields.has(field)) {
            setupPasswordField(field);
        }

    });
}


// ============================================================
// Setup password field
// ============================================================

function setupPasswordField(field) {

    passwordFields.set(field, {
        timer: null,
        version: 0
    });

    createSecurityPanel(field);

    field.addEventListener(
        "input",
        () => analyzePassword(field)
    );

    // Initial state
    updatePanel(field, {
        strength: "Waiting",
        score: 0,
        pattern: "Start typing...",
        breach: "Not checked"
    });
}


// ============================================================
// Create UI
// ============================================================

function createSecurityPanel(field) {

    const panel = document.createElement("div");

    panel.className = "psc-panel";

    panel.innerHTML = `
        <div class="psc-header">
            <span class="psc-status">🔐 Password Security</span>
        </div>

        <div class="psc-strength">
            Strength: <strong class="psc-strength-value">
                Waiting
            </strong>
        </div>

        <div class="psc-meter">
            <div class="psc-meter-fill"></div>
        </div>

        <div class="psc-pattern">
            🔍 Pattern:
            <span>Start typing...</span>
        </div>

        <div class="psc-breach">
            🛡️ Exposure:
            <span>Not checked</span>
        </div>

        <div class="psc-tip"></div>
    `;

    field.insertAdjacentElement(
        "afterend",
        panel
    );

    field._pscPanel = panel;
}


// ============================================================
// Analyze password
// ============================================================

function analyzePassword(field) {

    const password = field.value;

    const state = passwordFields.get(field);

    if (!state) {
        return;
    }

    // Increase version
    state.version++;

    const currentVersion = state.version;

    // Cancel previous breach timer
    if (state.timer) {

        clearTimeout(state.timer);

        state.timer = null;
    }

    // Empty password
    if (!password) {

        updatePanel(field, {
            strength: "Waiting",
            score: 0,
            pattern: "Start typing...",
            breach: "Not checked",
            tip: ""
        });

        return;
    }


    // ========================================================
    // Local analysis
    // ========================================================

    const result = calculateStrength(password);

    const pattern = detectPattern(password);

    const tip = getRecommendation(
        result,
        pattern
    );


    updatePanel(field, {
        strength: result.strength,
        score: result.score,
        pattern: pattern,
        breach: "Waiting...",
        tip: tip
    });


    // ========================================================
    // Wait until user stops typing
    // ========================================================

    state.timer = setTimeout(() => {

        checkBreach(
            password,
            field,
            currentVersion
        );

    }, 2000);
}


// ============================================================
// Strength calculation
// ============================================================

function calculateStrength(password) {

    let score = 0;

    // Length
    if (password.length >= 16) {

        score += 35;

    } else if (password.length >= 12) {

        score += 25;

    } else if (password.length >= 8) {

        score += 15;
    }


    // Uppercase
    if (/[A-Z]/.test(password)) {

        score += 15;
    }


    // Lowercase
    if (/[a-z]/.test(password)) {

        score += 15;
    }


    // Numbers
    if (/[0-9]/.test(password)) {

        score += 15;
    }


    // Special characters
    if (
        /[!@#$%^&*(),.?":{}|<>_\-+=/[\]\\]/.test(password)
    ) {

        score += 15;
    }


    // Common passwords
    const commonPatterns = [
        "password",
        "123456",
        "12345678",
        "qwerty",
        "admin",
        "welcome",
        "letmein",
        "abc123"
    ];

    const lower = password.toLowerCase();

    if (
        commonPatterns.some(
            pattern => lower.includes(pattern)
        )
    ) {

        score -= 30;
    }


    // Sequential numbers
    if (
        /(0123|1234|2345|3456|4567|5678|6789)/
        .test(password)
    ) {

        score -= 15;
    }


    // Repeated characters
    if (
        /(.)\1\1/.test(password)
    ) {

        score -= 10;
    }


    score = Math.max(
        0,
        Math.min(100, score)
    );


    let strength;

    if (score < 30) {

        strength = "Very Weak";

    } else if (score < 50) {

        strength = "Weak";

    } else if (score < 70) {

        strength = "Moderate";

    } else if (score < 85) {

        strength = "Strong";

    } else {

        strength = "Very Strong";
    }


    return {
        score,
        strength
    };
}


// ============================================================
// Pattern detection
// ============================================================

function detectPattern(password) {

    const lower = password.toLowerCase();


    const commonWords = [
        "password",
        "admin",
        "welcome",
        "qwerty",
        "letmein",
        "football",
        "monkey"
    ];


    for (const word of commonWords) {

        if (lower.includes(word)) {

            return `Common word + additional characters (${word})`;
        }
    }


    // Word + year
    if (
        /^[A-Za-z]{3,}(19|20)\d{2}$/
        .test(password)
    ) {

        return "Word + Year";
    }


    // Word + numbers
    if (
        /^[A-Za-z]+\d+$/.test(password)
    ) {

        return "Word + Numbers";
    }


    // Word + special + numbers
    if (
        /^[A-Za-z]{3,}[!@#$%^&*]+\d+$/
        .test(password)
    ) {

        return "Word/Name + Special Character + Numbers";
    }


    // Numbers only
    if (
        /^\d+$/.test(password)
    ) {

        return "Numbers Only";
    }


    // Letters only
    if (
        /^[A-Za-z]+$/.test(password)
    ) {

        return "Letters Only";
    }


    // Sequential numbers
    if (
        /(0123|1234|2345|3456|4567|5678|6789)/
        .test(password)
    ) {

        return "Sequential Number Pattern";
    }


    // Repeated characters
    if (
        /(.)\1\1/.test(password)
    ) {

        return "Repeated Character Pattern";
    }


    return "No obvious predictable pattern";
}


// ============================================================
// Recommendation
// ============================================================

function getRecommendation(
    result,
    pattern
) {

    const recommendations = [];


    if (result.score < 50) {

        recommendations.push(
            "Use a longer password."
        );
    }


    if (
        pattern.includes("Common")
    ) {

        recommendations.push(
            "Avoid common words."
        );
    }


    if (
        pattern.includes("Year")
    ) {

        recommendations.push(
            "Avoid predictable years."
        );
    }


    if (
        pattern.includes("Sequential")
    ) {

        recommendations.push(
            "Avoid sequences such as 1234."
        );
    }


    if (
        pattern.includes("Repeated")
    ) {

        recommendations.push(
            "Avoid repeated characters."
        );
    }


    if (
        recommendations.length === 0
    ) {

        return "💡 Use a unique password that you don't reuse elsewhere.";
    }


    return "💡 " + recommendations.join(" ");
}


// ============================================================
// Update UI
// ============================================================

function updatePanel(
    field,
    data
) {

    const panel = field._pscPanel;

    if (!panel) {
        return;
    }


    const strengthElement =
        panel.querySelector(
            ".psc-strength-value"
        );


    const meter =
        panel.querySelector(
            ".psc-meter-fill"
        );


    const pattern =
        panel.querySelector(
            ".psc-pattern span"
        );


    const breach =
        panel.querySelector(
            ".psc-breach span"
        );


    const tip =
        panel.querySelector(
            ".psc-tip"
        );


    strengthElement.textContent =
        data.strength;


    meter.style.width =
        `${data.score || 0}%`;


    pattern.textContent =
        data.pattern;


    breach.textContent =
        data.breach;


    tip.textContent =
        data.tip || "";


    // Remove old strength classes
    panel.classList.remove(
        "psc-weak",
        "psc-moderate",
        "psc-strong"
    );


    if (
        data.strength === "Very Weak" ||
        data.strength === "Weak"
    ) {

        panel.classList.add(
            "psc-weak"
        );

    } else if (
        data.strength === "Moderate"
    ) {

        panel.classList.add(
            "psc-moderate"
        );

    } else if (
        data.strength === "Strong" ||
        data.strength === "Very Strong"
    ) {

        panel.classList.add(
            "psc-strong"
        );
    }
}


// ============================================================
// HIBP breach check
// ============================================================

async function checkBreach(
    password,
    field,
    version
) {

    const state =
        passwordFields.get(field);


    // Password field may have disappeared
    if (!state) {
        return;
    }


    // Password changed
    if (
        state.version !== version
    ) {

        return;
    }


    try {

        // =====================================================
        // Hash password locally
        // =====================================================

        const encoder =
            new TextEncoder();

        const data =
            encoder.encode(password);


        const hashBuffer =
            await crypto.subtle.digest(
                "SHA-1",
                data
            );


        const hashArray =
            Array.from(
                new Uint8Array(hashBuffer)
            );


        const hash =
            hashArray
                .map(
                    byte =>
                        byte.toString(16)
                            .padStart(2, "0")
                )
                .join("")
                .toUpperCase();


        // =====================================================
        // k-anonymity
        // =====================================================

        const prefix =
            hash.substring(0, 5);


        const suffix =
            hash.substring(5);


        const response =
            await fetch(
                `https://api.pwnedpasswords.com/range/${prefix}`,
                {
                    headers: {
                        "User-Agent":
                            "Password-Security-Checker"
                    }
                }
            );


        if (!response.ok) {

            throw new Error(
                "HIBP request failed"
            );
        }


        const text =
            await response.text();


        // =====================================================
        // Find suffix
        // =====================================================

        let count = 0;


        const lines =
            text.split("\n");


        for (
            const line of lines
        ) {

            const parts =
                line.trim().split(":");


            if (
                parts.length !== 2
            ) {

                continue;
            }


            const returnedSuffix =
                parts[0].toUpperCase();


            if (
                returnedSuffix === suffix
            ) {

                count =
                    parseInt(
                        parts[1],
                        10
                    );

                break;
            }
        }


        // =====================================================
        // Make sure password is still current
        // =====================================================

        if (
            state.version !== version
        ) {

            return;
        }


        if (count > 0) {

            updateBreachUI(
                field,
                `⚠ Found in breach data (${count.toLocaleString()} times)`,
                true
            );

        } else {

            updateBreachUI(
                field,
                "✓ Not found in checked breach dataset",
                false
            );
        }


    } catch (error) {

        console.error(
            "Breach check error:",
            error
        );


        if (
            state.version !== version
        ) {

            return;
        }


        updateBreachUI(
            field,
            "Unable to check",
            false
        );
    }
}


// ============================================================
// Update breach UI
// ============================================================

function updateBreachUI(
    field,
    message,
    exposed
) {

    const panel =
        field._pscPanel;


    if (!panel) {
        return;
    }


    const breach =
        panel.querySelector(
            ".psc-breach span"
        );


    breach.textContent =
        message;


    if (exposed) {

        panel.classList.add(
            "psc-exposed"
        );

    } else {

        panel.classList.remove(
            "psc-exposed"
        );
    }
}


// ============================================================
// Detect dynamically-created password fields
// ============================================================

const observer =
    new MutationObserver(
        () => {
            findPasswordFields();
        }
    );


observer.observe(
    document.documentElement,
    {
        childList: true,
        subtree: true
    }
);


// ============================================================
// Initial scan
// ============================================================

findPasswordFields();