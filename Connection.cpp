#include <utility>
#include <vector>
#include "Connection.h"
#include "ShibbolethManager.h"

connection::connection(boost::asio::ip::tcp::socket socket)
    : socket_(std::move(socket))
    , buffer_mutex_{0}
    , stoped_(false)
    , working_(false)
{
}

void connection::start()
{
    do_read();
}

void connection::stop()
{
    stoped_ = true;
    socket_.close();
}

void connection::do_read()
{
    auto self(shared_from_this());
    socket_.async_read_some(boost::asio::buffer(buffer_),
    [this, self](boost::system::error_code ec, std::size_t bytes_transferred)
    {
        if (!ec)
        {
            buffer_[bytes_transferred] = '\0';
            auto pBuffer = GetFreeBuffer();
            if(ShibbolethManager::Instance().GetShibboleth(buffer_.data(), bytes_transferred, pBuffer))
            {
                write(pBuffer);
            }
            do_read();
        }
        else if (ec != boost::asio::error::operation_aborted)
        {
            stop();
        }
    });
}

void connection::do_write(std::shared_ptr<BufferT> buffer)
{
    working_ = true;
    auto self(shared_from_this());
    int32_t length = *((int32_t*)buffer->data());
    boost::asio::async_write(socket_, boost::asio::buffer(buffer->data() + 4, length),
    [this, self, length, buffer](boost::system::error_code ec, std::size_t tran)
    {
        working_ = false;
        if (!ec && tran == length)
        {
            {
                boost::detail::spinlock::scoped_lock __lock(buffer_mutex_);
                free_buffers_.push(buffer);
            }
            if(0 != out_buffers_.size())
            {
                auto firstBuffer = out_buffers_.front();
                out_buffers_.pop();
                do_write(firstBuffer);
            }
        }
        else
        {
            stop();
        }
    });
}

std::shared_ptr<BufferT> connection::GetFreeBuffer()
{
    boost::detail::spinlock::scoped_lock __lock(buffer_mutex_);
    if(0 == free_buffers_.size())
    {
	free_buffers_.push(std::make_shared<BufferT>());
    }

    auto pBuffer = free_buffers_.top();
    free_buffers_.pop();

    return pBuffer;
}

void connection::write(std::shared_ptr<BufferT> pBuffer)
{
    if(working_)
    {
	out_buffers_.push(pBuffer);
    }
    else
    {
	do_write(pBuffer);
    }

}

void connection::send(const char* buffer, int32_t length)
{
    if(!stoped_)
    {
	auto pBuffer = GetFreeBuffer();

	*((int32_t*)pBuffer->data()) = length;
	memcpy(pBuffer->data() + 4, buffer, length);

	socket_.get_io_service().post([this, pBuffer]()
	{
	    write(pBuffer);
	});
    }
}
