// Safe: Uses Object.create(null) and filters dangerous keys
function safeMerge(target, source) {
    const result = Object.create(null);
    for (const key of Object.keys(source)) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
        result[key] = source[key];
    }
    return result;
}
