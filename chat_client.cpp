#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/json.hpp>
#include <iostream>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace json = boost::json;
using tcp = asio::ip::tcp;

// Function to send a basic HTTP request using Boost.Beast (synchronous, plain TCP)
std::string send_request(
    const std::string& host,                  // e.g., "api.example.com"
    const std::string& port,                  // e.g., "80" or "443" (for HTTPS you'd need SSL setup)
    http::verb method,                        // HTTP method, e.g., http::verb::post or http::verb::get
    const std::string& target,                // The path/resource being requested, e.g., "/v1/data"
    const std::string& body = ""              // Optional request body (for POST/PUT)
) {
    try {
        // Create an I/O context required for all I/O operations
        asio::io_context ioc;

        // Create a resolver to turn the host name into a TCP endpoint
        tcp::resolver resolver(ioc);

        // Create the TCP stream for connecting and communicating
        beast::tcp_stream stream(ioc);

        // Resolve the host and port into a list of endpoints
        auto const results = resolver.resolve(host, port);

        // Establish a connection to one of the resolved endpoints
        stream.connect(results);

        // Build the HTTP request message
        http::request<http::string_body> req{ method, target, 11 };     // HTTP/1.1
        req.set(http::field::host, host);                               // Required: Host header
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);   // Optional: Identifies the client
        req.set(http::field::content_type, "application/json");         // Optional: for JSON bodies
        req.body() = body;                                              // Set the request body (if any)
        req.prepare_payload();                                          // Sets Content-Length and finalizes headers

        // Send the HTTP request to the remote host
        http::write(stream, req);

        // Buffer for receiving data
        beast::flat_buffer buffer;

        // Container for the HTTP response
        http::response<http::string_body> res;

        // Receive the response
        http::read(stream, buffer, res);

        // Return only the response body as a string
        return res.body();
    }
    catch (std::exception& e) {

        // Return the exception message prefixed with "Client error:"
        return std::string("Client error: ") + e.what();
    }
}



int main() {
    std::string host = "127.0.0.1";
    std::string port = "8080";

    while (true) {
        std::string command;
        std::cout << "Enter command (status/greet/exit): ";
        std::cin >> command;

        if (command == "status") {
            std::string response = send_request(host, port, http::verb::get, "/status");
            std::cout << "Server Response: " << response << "\n\n";
        }
        else if (command == "greet") {
            std::string name;
            std::cout << "Enter name: ";
            std::cin >> name;

            json::object request;
            request["name"] = name;
            std::string request_str = json::serialize(request);

            std::string response = send_request(host, port, http::verb::post, "/greet", request_str);
            std::cout << "Server Response: " << response << "\n\n";
        }
        else if (command == "exit") {
            break;
        }
        else {
            std::cout << "Invalid command!\n";
        }
    }

    return 0;
}