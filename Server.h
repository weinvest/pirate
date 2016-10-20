#ifndef _DISPATCH_SERVER_H
#define _DISPATCH_SERVER_H

#include <boost/asio.hpp>
#include <string>
#include <set>

class connection;
class Server
{
public:
  Server(const Server&) = delete;
  Server& operator=(const Server&) = delete;

  /// Construct the server to listen on the specified TCP address and port, and
  /// serve up files from the given directory.
  explicit Server(const std::string& address, const std::string& port);

  /// Run the server's io_service loop.
  void run();

  std::set<std::shared_ptr<connection>>& get_connections() { return mConnections; }
private:
  /// Perform an asynchronous accept operation.
  void do_accept();

  /// Wait for a request to stop the server.
  void do_await_stop();

  /// The io_service used to perform asynchronous operations.
  boost::asio::io_service io_service_;

  /// The signal_set is used to register for process termination notifications.
  boost::asio::signal_set signals_;

  /// Acceptor used to listen for incoming connections.
  boost::asio::ip::tcp::acceptor acceptor_;

  /// The connection manager which owns all live connections.
  std::set<std::shared_ptr<connection>> mConnections;
  /// The next socket to be accepted.
  boost::asio::ip::tcp::socket socket_;

};
#endif
