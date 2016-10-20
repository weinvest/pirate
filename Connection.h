#ifndef _CONNECTION_H
#define _CONNECTION_H

#include <array>
#include <memory>
#include <mutex>
#include <stack>
#include <queue>
#include <boost/asio.hpp>
#include <boost/smart_ptr/detail/spinlock.hpp>

class connection_manager;

/// Represents a single connection from a client.
class connection: public std::enable_shared_from_this<connection>
{
public:
    typedef std::array<char, 8192> BufferT;
    connection(const connection&) = delete;
    connection& operator=(const connection&) = delete;

    /// Construct a connection with the given socket.
    explicit connection(boost::asio::ip::tcp::socket socket);

    /// Start the first asynchronous operation for the connection.
    void start();

    /// Stop all asynchronous operations associated with the connection.
    void stop();

    void send(const char* buffer, int32_t length);

    bool stoped() const { return stoped_; }
private:
    std::shared_ptr<BufferT> GetFreeBuffer();
    void write(std::shared_ptr<BufferT> pBuffer);
    /// Perform an asynchronous read operation.
    void do_read();

    /// Perform an asynchronous write operation.
    void do_write(std::shared_ptr<BufferT> buffer);

    /// Socket for the connection.
    boost::asio::ip::tcp::socket socket_;

    /// Buffer for incoming data.
    BufferT buffer_;

    std::queue<std::shared_ptr<BufferT>> out_buffers_;
    std::stack<std::shared_ptr<BufferT>> free_buffers_;
    boost::detail::spinlock buffer_mutex_;
    bool stoped_;
    bool working_;
};

typedef std::shared_ptr<connection> connection_ptr;

#endif
