#pragma once
#include "basic.h"
#include <atomic>

namespace MyProxy {

	template <typename Protocol>
	class AbstractProxySession : 
		public BasicProxySession, 
		public std::enable_shared_from_this<AbstractProxySession<Protocol>>
	{
	public:
		struct TraitsProtoType;
		AbstractProxySession(SessionId id, boost::asio::io_service &io, std::string loggerName = "Session") :
			BasicProxySession(id,io, loggerName),
			m_socket(io), m_writeStrand(io) {}
		virtual ~AbstractProxySession() {
			//std::cout << "~AbstractProxySession\n";
		}
		//Get m_socket.
		typename Protocol::socket& socket() { return m_socket; }
		virtual void start() = 0;
		virtual void stop() override;
		//destroy session, if !notified, notify peer
		virtual void destroy(bool notified = false) override;
		virtual void setRunning(bool running) override {
			_running.exchange(running);
		}
		virtual bool running() override {
			return _running.load(); // ???
		}
	protected:
		//Read socket and write to tunnel.
		virtual void startForwarding();
		virtual void startForwarding_impl();
		//Write to socket.
		void write(std::shared_ptr<DataVec> dataPtr);
		void write_impl();
		//Get parent tunnel.
		std::atomic<bool> _running = false;
	private:
		typename Protocol::socket m_socket;
		boost::asio::strand m_writeStrand;
		std::queue<std::shared_ptr<DataVec>> m_writeQueue;
		//std::array<char,1024> m_readBuffer;
		boost::asio::streambuf m_readBuffer2;
	};

	template<>
	struct AbstractProxySession<boost::asio::ip::tcp>::TraitsProtoType {
		static constexpr ProtoType type = ProtoType::Tcp;
	};
	template<>
	struct AbstractProxySession<boost::asio::ip::udp>::TraitsProtoType {
		static constexpr ProtoType type = ProtoType::Udp;
	};

	template<typename Protocol>
	inline void AbstractProxySession<Protocol>::stop()
	{
		auto self = this->shared_from_this();
		if (m_socket.is_open()) {
			boost::system::error_code ec;
			m_socket.shutdown(m_socket.shutdown_both, ec);
			if (ec) {
				logger()->debug("ID: {} Shutdown error: {}",id(), ec.message());
			}
			ec.clear();
			m_socket.close(ec);
			if (ec) {
				logger()->debug("ID: {} Close error: {}",id(), ec.message());
			}
		}
		unused(self);
	}

	template<typename Protocol>
	inline void AbstractProxySession<Protocol>::destroy(bool notified)
	{
		auto self = this->shared_from_this();
		if (_running.exchange(false)) {
			if (this->tunnel()->manager().remove(this->id())) {
				if(!notified)
					this->tunnel()->sessionDestroyNotify(this->id());
			}
		}
		unused(self);
	}

	template<typename Protocol>
	inline void AbstractProxySession<Protocol>::startForwarding()
	{
		_running.store(true);
		this->onReceived = [this](std::shared_ptr<SessionPackage> package) {
			if(_running.load()) //...
				write(std::make_shared<DataVec>(std::move(package->data)));
		};
		//m_readBuffer.fill('\0');
		startForwarding_impl();
	}

	template<typename Protocol>
	inline void AbstractProxySession<Protocol>::startForwarding_impl()
	{
		using namespace boost::asio;
		m_socket.async_receive(m_readBuffer2.prepare(1024 * 4), [this, self = this->shared_from_this()](const boost::system::error_code &ec, size_t bytes) {
			if (ec) {
				if (!_running.load() || ec == boost::asio::error::operation_aborted)
					return;
				logger()->debug("ID: {} Destroy, reason: {}", id(), ec.message());
				destroy();
				return;
			}
			auto data = buffer_cast<const char*>(m_readBuffer2.data());
			SessionPackage package{ id(),DataVec{ data, data + bytes } };
			auto dp = std::make_shared<DataVec>(package.toDataVec());
			tunnel()->write(std::move(dp));
			m_readBuffer2.consume(bytes);
			startForwarding_impl();
		});
	}

	template<typename Protocol>
	inline void AbstractProxySession<Protocol>::write(std::shared_ptr<DataVec> dataPtr)
	{
		//logger()->trace("AbstractProxySession<Protocol>::write() {} bytes write method posted", dataPtr->size());
		m_writeStrand.post([this, dataPtr = std::move(dataPtr), self = this->shared_from_this()]{
			if (!_running.load())
				return;
			//logger()->trace("AbstractProxySession<Protocol>::write() -> Lambda: {} bytes push to m_writeQueue", dataPtr->size());
			m_writeQueue.push(std::move(dataPtr));
			if (m_writeQueue.size() > 1) {
				return;
			}
			else {
				//m_writeStrand.post(std::bind(&AbstractProxySession<Protocol>::write_impl, this));
				write_impl();
			}
		});
	}

	template<>
	void AbstractProxySession<boost::asio::ip::tcp>::write_impl();
	template<>
	void AbstractProxySession<boost::asio::ip::udp>::write_impl();
}