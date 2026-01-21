// Base64URL encoding/decoding utilities
function base64URLEncode(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (const byte of bytes) {
        str += String.fromCharCode(byte);
    }
    return btoa(str)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

function base64URLDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) {
        str += '=';
    }
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// Register a new user with passkey
async function register(username) {
    // Step 1: Begin registration
    const beginResponse = await fetch('/api/register/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
    });

    if (!beginResponse.ok) {
        const text = await beginResponse.text();
        throw new Error(text || 'Failed to start registration');
    }

    const { options, sessionId } = await beginResponse.json();

    // Convert base64url strings to ArrayBuffers
    options.publicKey.challenge = base64URLDecode(options.publicKey.challenge);
    options.publicKey.user.id = base64URLDecode(options.publicKey.user.id);

    if (options.publicKey.excludeCredentials) {
        options.publicKey.excludeCredentials = options.publicKey.excludeCredentials.map(cred => ({
            ...cred,
            id: base64URLDecode(cred.id)
        }));
    }

    // Step 2: Create credential using WebAuthn API
    const credential = await navigator.credentials.create(options);

    // Step 3: Finish registration
    const attestationResponse = {
        id: credential.id,
        rawId: base64URLEncode(credential.rawId),
        type: credential.type,
        response: {
            clientDataJSON: base64URLEncode(credential.response.clientDataJSON),
            attestationObject: base64URLEncode(credential.response.attestationObject)
        }
    };

    const finishResponse = await fetch(
        `/api/register/finish?username=${encodeURIComponent(username)}&sessionId=${encodeURIComponent(sessionId)}`,
        {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(attestationResponse)
        }
    );

    if (!finishResponse.ok) {
        const text = await finishResponse.text();
        throw new Error(text || 'Failed to complete registration');
    }

    return await finishResponse.json();
}

// Login with passkey
async function login(username) {
    // Step 1: Begin login
    const beginResponse = await fetch('/api/login/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
    });

    if (!beginResponse.ok) {
        const text = await beginResponse.text();
        throw new Error(text || 'Failed to start login');
    }

    const { options, sessionId } = await beginResponse.json();

    // Convert base64url strings to ArrayBuffers
    options.publicKey.challenge = base64URLDecode(options.publicKey.challenge);

    if (options.publicKey.allowCredentials) {
        options.publicKey.allowCredentials = options.publicKey.allowCredentials.map(cred => ({
            ...cred,
            id: base64URLDecode(cred.id)
        }));
    }

    // Step 2: Get credential using WebAuthn API
    const credential = await navigator.credentials.get(options);

    // Step 3: Finish login
    const assertionResponse = {
        id: credential.id,
        rawId: base64URLEncode(credential.rawId),
        type: credential.type,
        response: {
            clientDataJSON: base64URLEncode(credential.response.clientDataJSON),
            authenticatorData: base64URLEncode(credential.response.authenticatorData),
            signature: base64URLEncode(credential.response.signature),
            userHandle: credential.response.userHandle
                ? base64URLEncode(credential.response.userHandle)
                : null
        }
    };

    const finishResponse = await fetch(
        `/api/login/finish?username=${encodeURIComponent(username)}&sessionId=${encodeURIComponent(sessionId)}`,
        {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(assertionResponse)
        }
    );

    if (!finishResponse.ok) {
        const text = await finishResponse.text();
        throw new Error(text || 'Failed to complete login');
    }

    return await finishResponse.json();
}

// Get current user info
async function getUser() {
    const response = await fetch('/api/user');

    if (!response.ok) {
        throw new Error('Not authenticated');
    }

    return await response.json();
}

// Logout
async function logout() {
    await fetch('/api/logout', { method: 'POST' });
}

// Add a new passkey (for authenticated users)
async function addPasskey(name) {
    // Step 1: Begin adding passkey
    const beginResponse = await fetch('/api/passkey/add/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    });

    if (!beginResponse.ok) {
        const text = await beginResponse.text();
        throw new Error(text || 'Failed to start adding passkey');
    }

    const { options, sessionId } = await beginResponse.json();

    // Convert base64url strings to ArrayBuffers
    options.publicKey.challenge = base64URLDecode(options.publicKey.challenge);
    options.publicKey.user.id = base64URLDecode(options.publicKey.user.id);

    if (options.publicKey.excludeCredentials) {
        options.publicKey.excludeCredentials = options.publicKey.excludeCredentials.map(cred => ({
            ...cred,
            id: base64URLDecode(cred.id)
        }));
    }

    // Step 2: Create credential using WebAuthn API
    const credential = await navigator.credentials.create(options);

    // Step 3: Finish adding passkey
    const attestationResponse = {
        id: credential.id,
        rawId: base64URLEncode(credential.rawId),
        type: credential.type,
        response: {
            clientDataJSON: base64URLEncode(credential.response.clientDataJSON),
            attestationObject: base64URLEncode(credential.response.attestationObject)
        }
    };

    const finishResponse = await fetch(
        `/api/passkey/add/finish?sessionId=${encodeURIComponent(sessionId)}&name=${encodeURIComponent(name || 'Passkey')}`,
        {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(attestationResponse)
        }
    );

    if (!finishResponse.ok) {
        const text = await finishResponse.text();
        throw new Error(text || 'Failed to add passkey');
    }

    return await finishResponse.json();
}

// Delete a passkey
async function deletePasskey(id) {
    const response = await fetch(`/api/passkey?id=${encodeURIComponent(id)}`, {
        method: 'DELETE'
    });

    if (!response.ok) {
        const text = await response.text();
        throw new Error(text || 'Failed to delete passkey');
    }

    return await response.json();
}

// Rename a passkey
async function renamePasskey(id, newName) {
    const response = await fetch('/api/passkey', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, name: newName })
    });

    if (!response.ok) {
        const text = await response.text();
        throw new Error(text || 'Failed to rename passkey');
    }

    return await response.json();
}
