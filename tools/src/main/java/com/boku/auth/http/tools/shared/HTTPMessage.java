package com.boku.auth.http.tools.shared;

import com.boku.auth.http.AuthorizationHeader;
import com.boku.auth.http.httpmessage.CanonicalHttpHeader;
import com.boku.auth.http.httpmessage.CanonicalHttpMessage;
import com.boku.auth.http.httpmessage.CanonicalHttpRequest;
import com.boku.auth.http.httpmessage.CanonicalHttpResponse;
import com.boku.util.DigestFactory;
import com.boku.util.HexCodec;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.boku.auth.http.tools.shared.CmdUtil.*;

/**
 * Util class for working with HTTP messages in the tools package.<br>
 * <br>
 * <b>Don't use this in production!</b>
 * It is for debugging and pretty printing only, and provides nothing that standard tools should not already.
 */
public class HTTPMessage {

    public static class Header {
        public String name;
        public String value;

        public Header(String name, String value) {
            this.name = name;
            this.value = value;
        }
    }

    public String startLine;
    public List<Header> headers = new ArrayList<>();
    public byte[] entity;
    public String charset;

    public boolean isRequest() {
        if (startLine.matches(".* HTTP/[0-9.]+$")) {
            return true;
        }
        if (startLine.startsWith("HTTP/")) {
            return false;
        }
        return startLine.matches("^[A-Z]{3,10}\\s+\\S+$"); // Uh... probably I guess?
    }

    /**
     * Output the HTTP request or response in text form, roughly as it would have been seen on the wire.
     */
    StringBuilder dump(StringBuilder out) {
        out.append(startLine).append('\n');
        for (Header hdr : headers) {
            out.append(hdr.name).append(": ").append(hdr.value.trim()).append('\n');
        }
        out.append('\n');
        if (entity != null) {
            if (charset != null) {
                try {
                    out.append(new String(entity, charset));
                } catch (UnsupportedEncodingException ex) {
                    warn("Charset " + charset + " specified in Content-Type header unsupported, will display as ASCII...");
                    out.append(new String(entity, StandardCharsets.US_ASCII));
                }
            } else {
                out.append(new String(entity, StandardCharsets.US_ASCII));
            }
        }
        return out;
    }

    @Override
    public String toString() {
        return dump(new StringBuilder()).toString();
    }

    /**
     * Get the entity in string form. This assumes it is text in the first place - if it's not, you'll get interesting
     * results here.
     */
    public String entityString() {
        if (entity == null) {
            return null;
        }
        if (charset != null) {
            try {
                return new String(entity, charset);
            } catch (UnsupportedEncodingException ex) {
                warn("Charset " + charset + " specified in Content-Type header unsupported, outputting as ASCII...");
            }
        } else {
            warn("No Content-Type charset specified, outputting as ASCII...");
        }
        return new String(entity, StandardCharsets.US_ASCII);
    }

    int findHeaders(String name, Consumer<Header> consumer) {
        int count = 0;
        name = name.toLowerCase();
        for (Header header : headers) {
            if (name.equals(header.name.trim().toLowerCase())) {
                consumer.accept(header);
                count++;
            }
        }
        return count;
    }

    public Header findFirstHeader(String name) {
        name = name.toLowerCase();
        for (Header header : headers) {
            if (name.equals(header.name.trim().toLowerCase())) {
                return header;
            }
        }
        return null;
    }

    /**
     * Turn this HTTPMessage into a {@link CanonicalHttpRequest} or {@link CanonicalHttpResponse}.
     */
    public CanonicalHttpMessage canonicalize(AuthorizationHeader ah) {
        CanonicalHttpMessage r;
        if (isRequest()) {
            CanonicalHttpRequest req = new CanonicalHttpRequest();
            String[] reqParts = startLine.split("\\s+");
            if (reqParts.length < 2 || reqParts.length > 3) {
                throw new ParseException("Unrecognized request-line: " + startLine);
            }
            req.setMethod(reqParts[0].toUpperCase());
            String[] uriParts = reqParts[1].split("\\?", 2);
            req.setPath(uriParts[0]);
            if (uriParts.length == 2) {
                req.setQueryString(uriParts[1]);
            }
            r = req;
        } else {
            r = new CanonicalHttpResponse();
        }

        for (String signedHeaderName : ah.getSignedHeaders()) {
            int count = findHeaders(signedHeaderName, (hdr) -> r.getHeaders().add(new CanonicalHttpHeader(signedHeaderName, hdr.value.trim())));
            if (count == 0) {
                warn("HTTP message does not contain any " + signedHeaderName + " headers");
            }
        }

        if (entity != null) {
            byte[] digest = DigestFactory.getSHA256().digest(entity);
            r.setEntityDigest(HexCodec.encodeString(digest));
        }

        return r;
    }

    public static class ParseException extends RuntimeException {
        ParseException(String message) {
            super(message);
        }
    }

    /**
     * Attempt to parse a HTTP request or response from the raw HTTP protocol data as it would appear on the wire.
     */
    public static HTTPMessage parse(byte[] data) throws ParseException {
        HTTPMessage http = new HTTPMessage();

        int line = 1;
        int start = 0;
        int end = findEOL(data, start);
        if (end < 0) {
            throw new ParseException("No line ending on the first line");
        }

        // HTTP start-line
        http.startLine = ascii(data, start, end);
        start = endOfEOL(data, end);
        line++;

        // Extract headers
        while (start < data.length) {
            end = findEOL(data, start);
            if (end < 0) {
                throw new ParseException("Could not find EOL while parsing headers at line " + line + ". All HTTP requests must end with a blank line.");
            }
            if (start == end) {
                break;
            }

            int colon = indexOf(data, (byte)':', start, end);
            if (colon < 0) {
                throw new ParseException("Header at line " + line + " has no name:value delimiter");
            }
            Header hdr = new Header(
                ascii(data, start, colon),
                ascii(data, colon + 1, end)
            );
            http.headers.add(hdr);

            start = endOfEOL(data, end);
            line++;
        }
        start = endOfEOL(data, end);

        // Check for unsupported transfer-encoding
        {
            Header h = http.findFirstHeader("Transfer-Encoding");
            if (h != null) {
                throw new ParseException("Not implemented: Transfer-Encoding: " + h.value);
            }
        }

        // Extract the entity
        {
            int entityLen = data.length - start;

            Header clh = http.findFirstHeader("Content-Length");
            if (clh != null) {
                int clv = Integer.parseInt(clh.value.trim());
                if (clv > entityLen) {
                    throw new ParseException("Content-Length of " + clv + " extends past end of data (" + entityLen + " bytes remain)");
                }
                if (clv < entityLen) {
                    warn((entityLen - clv) + " extra bytes of data after Content-Length of " + clv + ", ignoring");
                }
                entityLen = clv;
            }

            if (entityLen > 0) {
                http.entity = new byte[entityLen];
                System.arraycopy(data, start, http.entity, 0, entityLen);
            }
        }

        // Get the charset if there is one
        determineCharset(http);

        return http;
    }

    public static void determineCharset(HTTPMessage http) {
        if (http.entity != null) {
            Header cth = http.findFirstHeader("Content-Type");
            if (cth == null) {
                warn("No Content-Type header present, will display as ASCII (does not affect signature)");
            } else {
                Matcher m = Pattern.compile("charset\\s*=\\s*['\"]?([^\\s\"]+)").matcher(cth.value);
                if (m.find()) {
                    http.charset = m.group(1);
                } else {
                    warn("Content-Type header does not specify charset, will display as ASCII (does not affect signature)");
                }
            }
        }
    }

    private static String ascii(byte[] data, int start, int end) {
        return new String(data, start, end - start, StandardCharsets.US_ASCII);
    }

    private static int findEOL(byte[] data, int from) {
        for (int i = from; i < data.length; i++) {
            if (data[i] == '\r' || data[i] == '\n') {
                return i;
            }
        }
        return -1;
    }

    private static int endOfEOL(byte[] data, int at) {
        if (data[at] == '\n') {
            return at + 1;
        }
        if (data[at] == '\r') {
            if (data[at + 1] == '\n') {
                return at + 2;
            }
            throw new ParseException("CR followed by 0x" + Integer.toHexString(0xFF&data[at+1]) + " at byte " + at);
        }
        throw new ParseException("Not a line ending: 0x" + Integer.toHexString(0xFF&data[at]) + " at byte " + at);
    }

    private static int indexOf(byte[] data, byte b, int from, int to) {
        for (int i = from; i < to; i++) {
            if (data[i] == b) {
                return i;
            }
        }
        return -1;
    }

}
