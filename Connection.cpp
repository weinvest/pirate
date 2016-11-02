#include <utility>
#include <vector>
#include "Connection.h"
#include "ShibbolethManager.h"
#include "Server.h"
boost::detail::spinlock connection::buffer_mutex_{0};
std::stack<BufferT*> connection::free_buffers_;
connection::connection(Server* parent, boost::asio::ip::tcp::socket socket)
    : mParent(parent)
    , socket_(std::move(socket))
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
    mParent->get_connections().erase(shared_from_this());
    std::cout<< "--one connection has stopped" << std::endl;
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
                write(pBuffer, true);
            }
            do_read();
        }
        else if (ec != boost::asio::error::operation_aborted)
        {
            std::cout << ShibbolethManager::currentTime() << ":read error : " << ec.message() << std::endl;
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
    boost::asio::transfer_all(),
    [this, self, length, buffer](boost::system::error_code ec, std::size_t tran)
    {
        working_ = false;
        if (!ec && tran == length)
        {
            if(0 != out_buffers_.size())
            {
                auto firstBuffer = out_buffers_.front();
                out_buffers_.pop_front();
                do_write(firstBuffer);
            }
        }
        else
        {
            std::cout << ShibbolethManager::currentTime() << ":write error: " << ec.message() << " message len:" << length << " transfered:" << tran << std::endl;
            stop();
        }
    });
}

std::shared_ptr<BufferT> connection::GetFreeBuffer()
{
    boost::detail::spinlock::scoped_lock __lock(buffer_mutex_);
    BufferT* rawBuffer = nullptr;
    if(0 == free_buffers_.size())
    {
        rawBuffer = new BufferT();
    }
    else
    {
        rawBuffer = free_buffers_.top();
        free_buffers_.pop();
    }

    std::function<void(void*)> deallocate = [](void* p)
    {
        boost::detail::spinlock::scoped_lock __lock(buffer_mutex_);
        free_buffers_.push((BufferT*)p);
    };

    return std::shared_ptr<BufferT>(rawBuffer, deallocate);
}


void connection::write(std::shared_ptr<BufferT> pBuffer, bool firstPri)
{
    if(working_)
    {
        if(firstPri)
        {
            out_buffers_.push_front(pBuffer);
        }
        else
        {
	        out_buffers_.push_back(pBuffer);
        }
    }
    else
    {
	    do_write(pBuffer);
    }

}

void connection::Send(std::shared_ptr<BufferT> pBuffer)
{
    if(!stoped_)
    {
    	socket_.get_io_service().post([this, pBuffer]()
    	{
    	    write(pBuffer, false);
    	});
    }
}
