#include "packages.h"

namespace MyProxy {

	IoHelper& operator<<(IoHelper&& io, const Package& package)
	{
		io << package.toDataVec();
		return io;
	}
	IoHelper& operator>>(IoHelper&& io, Package& package)
	{
		Package::SizeType size;
		io.getCastedValues<uint8_t, Package::SizeType>(package.type, size);
		return io;
	}

	IoHelper& operator<<(IoHelper&& io, const SessionPackage& package)
	{
		io.putCastedValues<uint8_t, Package::SizeType, SessionId, DataVec>(package.type, package.size(), package.sessionId, package.data);
		return io;
	}
	IoHelper& operator>>(IoHelper&& io, SessionPackage& package)
	{
		SessionPackage::SizeType size;
		io.getCastedValues<uint8_t, Package::SizeType, SessionId>(package.type, size, package.sessionId);
		package.data.resize(package.calcDataSize(size));
		io.getValues(package.data);
		//package.data = io.getValue<DataVec>(package.calcDataSize(size));
		return io;
	}

	IoHelper & operator<<(IoHelper && io, const NewSessionRequest & package)
	{
		io.putCastedValues<uint8_t, Package::SizeType, uint8_t, SessionId, uint8_t, uint8_t, DataVec, uint16_t>
			(package.type, package.size(), package.method, package.id, package.protoType, package.addrType, package.host, package.port);
		return io;
	}

	IoHelper & operator>>(IoHelper && io, NewSessionRequest & package)
	{
		SessionPackage::SizeType size;
		io.getCastedValues<uint8_t, Package::SizeType, uint8_t, SessionId, uint8_t, uint8_t>
			(package.type, size, package.method, package.id, package.protoType, package.addrType);
		package.host.resize(package.calcHostSize(size));
		io.getValues(package.host, package.port);
		return io;
	}

	IoHelper & operator>>(IoHelper & io, SessionDestoryNotify & package)
	{
		SessionPackage::SizeType size;
		io.getCastedValues<uint8_t, Package::SizeType, uint8_t, SessionId>
			(package.type, size, package.method, package.id);
		return io;
	}

}