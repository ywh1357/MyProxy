#include "abstractproxysession.h"

namespace MyProxy {

	template<>
	void AbstractProxySession<boost::asio::ip::tcp>::write_impl()
	{
		if (m_writeQueue.empty()) {
			//logger()->trace("AbstractProxySession<boost::asio::ip::tcp>::write_impl() m_writeQueue empty");
			return;
		}
		//logger()->trace("AbstractProxySession<boost::asio::ip::tcp>::write_impl() {} bytes write method start async_write", m_writeQueue.front()->size());
		async_write(m_socket, boost::asio::buffer(*m_writeQueue.front()), boost::asio::transfer_all(),
			m_writeStrand.wrap([this, self = shared_from_this()](const boost::system::error_code &ec, size_t bytes){
			m_writeQueue.pop(); //drop
			if (ec) {
				if (!_running.load())
					return;
				logger()->debug("ID: {} write error: {}", id(), ec.message());
				destroy();
				return;
			}
			if (!m_writeQueue.empty()) {
				//m_writeStrand.post(std::bind(&AbstractProxySession<boost::asio::ip::tcp>::write_impl, this));
				write_impl();
			}
		}));
	}

	template<>
	void AbstractProxySession<boost::asio::ip::udp>::write_impl()
	{
		//if (m_writeQueue.size() == 0) {
		//	return;
		//}
		m_socket.async_send(boost::asio::buffer(*m_writeQueue.front()),
			m_writeStrand.wrap([this, self = shared_from_this()](const boost::system::error_code &ec, size_t) {
			m_writeQueue.pop();
			if (ec) {
				if (!_running.load())
					return;
				logger()->debug("ID: {} write error: {}", id(), ec.message());
				destroy();
				return;
			}
			m_writeQueue.pop();
			if (!m_writeQueue.empty()) {
				//m_writeStrand.post(std::bind(&AbstractProxySession<boost::asio::ip::udp>::write_impl, this));
				write_impl();
			}
		}));
	}

}