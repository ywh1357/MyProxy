#include "abstractproxytunnel.h"
#include <botan/tls_client.h>

using namespace boost::asio;

namespace MyProxy {
	AbstractProxyTunnel::~AbstractProxyTunnel()
	{
		boost::system::error_code ec;
		connection().close(ec);
		if (ec) {
			logger()->debug("close error: {}", ec.message());
		}
		logger()->debug("destroyed");
	}
	void AbstractProxyTunnel::tls_emit_data(const uint8_t data[], size_t size)
	{
		write_ex(std::make_shared<DataVec>(DataVec{ data, data + size }));
	}
	void AbstractProxyTunnel::tls_record_received(uint64_t /*seq_no*/, const uint8_t data[], size_t size)
	{
		IoHelper io(&_readBuffer2);
		io.write(reinterpret_cast<const char*>(data), size);
		auto rawData = buffer_cast<const char*>(_readBuffer2.data());
		if (Package::remainBytes(rawData, _readBuffer2.size()) > 0)
			return;
		else {
			auto pkgSz = Package::getSize(rawData);
			auto pkgData = std::make_shared<DataVec>(pkgSz);
			io.read(*pkgData, pkgSz);
			//_readBuffer2.consume(pkgSz);
			handleRead(pkgData);
		}
	}
	void AbstractProxyTunnel::tls_alert(Botan::TLS::Alert alert)
	{
		auto vec = alert.serialize();
		logger()->error("Alert: {}:{}", alert.type_string(),std::string{ vec.begin(), vec.end() });
	}
	bool AbstractProxyTunnel::tls_session_established(const Botan::TLS::Session & session)
	{
		return false;
	}
	void AbstractProxyTunnel::write(std::shared_ptr<DataVec> dataPtr)
	{
		if (!_running.load())
			return;
		post(_strand, [this, dataPtr, self = shared_from_this()]{
			if (!_channel->is_active())
			return;
			try {
				_channel->send(reinterpret_cast<const uint8_t*>(dataPtr->data()), dataPtr->size());
			}
			catch (const std::exception &ex) {
				logger()->error("_channel->send() error: {}", ex.what());
				_channel->close();
				shutdown();
				disconnect();
			}
		});
	}
	void AbstractProxyTunnel::write_ex(std::shared_ptr<DataVec> dataPtr)
	{
		if (!_running.load())
			return;
		post(_strand, [this, dataPtr = std::move(dataPtr), self = shared_from_this()]{
			_writeQueue.push(std::move(dataPtr));
			if (_writeQueue.size() > 1) {
				return;
			}
			else {
				write_impl();
			}
		});
	}
	void AbstractProxyTunnel::write_impl()
	{
		async_write(connection(), boost::asio::buffer(*_writeQueue.front()), boost::asio::transfer_all(),
			bind_executor(_strand, [this, self = shared_from_this()](const boost::system::error_code &ec, size_t) {
			_writeQueue.pop(); //drop
				if (ec) {
					if (!_running.load())
						return;
					logger()->debug("AbstractProxyTunnel::write_impl() error: ", ec.message());
					shutdown(RunningState::shutdown_write);
					disconnect();
					return;
				}
				if (!_writeQueue.empty()) {
					write_impl();
				}
				else if (!_running.load()) {
					shutdown(RunningState::shutdown_write);
				}
			})
		);
	}
	void AbstractProxyTunnel::nextRead()
	{
		using namespace boost::asio;
		if (!_running.load())
			return;
		connection().async_read_some(_readBuffer.prepare(4 * 1024),
			bind_executor(_strand, [this, self = shared_from_this()](const boost::system::error_code &ec, size_t bytes){
				if (!_running.load() || _channel->is_closed())
					return;
				if (ec) {
					logger()->debug("AbstractProxyTunnel::nextRead() error: ", ec.message());
					shutdown(RunningState::shutdown_read);
					disconnect();
					return;
				}
				try {
					_channel->received_data(boost::asio::buffer_cast<const uint8_t*>(_readBuffer.data()), bytes);
				}
				catch (const std::exception &ex) {
					logger()->warn("_channel->received_data() error: {}", ex.what());
					shutdown(RunningState::shutdown_read);
					_channel->close();
					disconnect();
					return;
				}
				_readBuffer.consume(bytes);
				nextRead();
			})
		);
	}
	void AbstractProxyTunnel::disconnect()
	{
		if (!_running.exchange(false))
			return;
		manager().clear();
		if (onDisconnected)
			onDisconnected();
	}
	void AbstractProxyTunnel::shutdown(RunningState state)
	{
		using shutdown_type = boost::asio::socket_base::shutdown_type;
		auto op = state & ~RunningState(std::atomic_fetch_or(&_state, static_cast<uint8_t>(state)));
		boost::system::error_code ec;
		if (op & RunningState::shutdown_read) {
			ec.clear();
			connection().shutdown(shutdown_type::shutdown_receive, ec);
			if (ec) {
				logger()->debug("shutdown receive error: {}", ec.message());
			}
		}
		if (op & RunningState::shutdown_write) {
			ec.clear();
			connection().shutdown(shutdown_type::shutdown_send, ec);
			if (ec) {
				logger()->debug("shutdown send error: {}", ec.message());
			}
		}
	}

}