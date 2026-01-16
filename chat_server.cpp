#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <iostream>
#include <string>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = asio::ip::tcp;

// Функция, которая идет во "внешний мир" за данными
void do_proxy_forwarding(
    asio::io_context& ioc,
    http::request<http::string_body>& client_req, 
    http::response<http::string_body>& final_res
) {
    // 1. Извлекаем хост из заголовков (например, "google.com")
    std::string host = client_req["Host"];
    if (host.empty()) {
        final_res.result(http::status::bad_request);
        final_res.body() = "Missing Host header";
        final_res.prepare_payload();
        return;
    }

    // 2. Настраиваем соединение с целевым сервером
    tcp::resolver resolver(ioc);
    auto const results = resolver.resolve(host, "80"); // HTTP порт
    tcp::socket server_socket(ioc);
    asio::connect(server_socket, results.begin(), results.end());

    // 3. Отправляем полученный от браузера запрос дальше
    // Важно: для простого прокси лучше отключить Keep-Alive
    client_req.keep_alive(false);
    http::write(server_socket, client_req);

    // 4. Читаем ответ от настоящего сервера
    beast::flat_buffer buffer;
    http::read(server_socket, buffer, final_res);
}

void run_server(asio::io_context& ioc, unsigned short port) {
    tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), port));
    std::cout << "Proxy running on port " << port << "...\n";

    while (true) {
        tcp::socket client_socket(ioc);
        acceptor.accept(client_socket); // Ждем клиента (браузер)

        beast::flat_buffer buffer;
        http::request<http::string_body> req;
        
        try {
            // Читаем, что хочет клиент
            http::read(client_socket, buffer, req);

            // Создаем объект ответа, который мы заполним данными с сервера
            http::response<http::string_body> res;
            
            // Выполняем проксирование
            do_proxy_forwarding(ioc, req, res);

            // Отправляем результат обратно браузеру
            http::write(client_socket, res);
        }
        catch (std::exception& e) {
            std::cerr << "Error during forwarding: " << e.what() << "\n";
        }
    }
}

int main() {
    try {
        asio::io_context io_context;
        run_server(io_context, 8080);
    }
    catch (std::exception& e) {
        std::cerr << "Main error: " << e.what() << "\n";
    }
    return 0;
}