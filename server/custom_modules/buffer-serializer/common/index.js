/**
 * Buffer serializer
 *
 * This just includes the other libraries.  It's performing dependency
 * injection for the other files.  The whole set is written this way to
 * facilitate far easier testing.
 */
const serializer = require("./serializer");
module.exports = serializer;
