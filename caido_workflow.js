export async function run(input, sdk) {
  try {
    const request = input.request;
    if (!request) {
      sdk.console.log("No request present, skipping");
      return;
    }

    // Extract raw HTTP request
    const rawRequest = request.getRaw().toText();
    const b64Data = Buffer.from(rawRequest, "utf8").toString("base64");

    // Prepare JSON payload
    const payload = { data: b64Data };

    // Build a POST to our collector server
    const spec = new RequestSpec("http://127.0.0.1:8081/receive");
    spec.setMethod("POST");
    spec.setHeader("Content-Type", "application/json");
    spec.setBody(JSON.stringify(payload));

    // Send the request
    sdk.console.log("Sending raw request to collector");
    const resp = await sdk.requests.send(spec);

    // Log result status
    const status = resp.response ? resp.response.getStatusCode() : resp.status;
    sdk.console.log(`Collector responded with status ${status}`);
  } catch (error) {
    sdk.console.log(`Error sending to collector: ${error.message}`);
  }
}
