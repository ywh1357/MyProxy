#pragma once
#ifndef MYPROXY_IOHELPER
#define MYPROXY_IOHELPER

#include <iostream>
#include <vector>
#include <memory>
#include <tuple>
#include <boost/endian/conversion.hpp>

namespace MyProxy {

	//enum Tesst: uint8_t{ first, last };

	using DataVec = std::vector<char>;

	template <typename T>
	T hostToNetwork(T value) {
		return static_cast<T>(boost::endian::native_to_big(value));
	}

	template<typename T>
	T networkToHost(T value) {
		return static_cast<T>(boost::endian::big_to_native(value));
	}

	template <typename T>
	struct TnS {
		typedef T type;
		const size_t size;
		constexpr TnS(size_t size = sizeof(T)) :size(size) {}
	};

	constexpr TnS<uint8_t> _1B;
	constexpr TnS<uint16_t> _2B;
	constexpr TnS<uint32_t> _4B;
	constexpr TnS<uint64_t> _8B;
	using _datavec = TnS<DataVec>;

	template <typename TupleType, typename Func, size_t ...I>
	void for_each(TupleType& tuple, Func f, std::index_sequence<I...>) {
		std::initializer_list<int>{
			(f(std::get<I>(tuple)), 0)...
		};
	}

	class DataVecBuf : public std::streambuf {
	public:
		DataVecBuf(DataVec &vec) :vec(vec), first(vec.data()), last(vec.data() + vec.size()) {
			setg(vec.data(), vec.data(), vec.data() + vec.size());
			setp(vec.data(), vec.data() + vec.size(), vec.data() + vec.size());
		}
		int_type overflow(int_type ch) override {
			vec.push_back(ch);
			first = vec.data();
			last = vec.data() + vec.size();
			setg(first, first + (gptr() - eback()), first + (egptr() - eback()));
			setp(first, first + (pptr() - pbase()) + 1, last);
			return ch;
		}
		int_type underflow() override {
			auto current = gptr();
			if (current < last) {
				setg(eback(), current, last);
				return *current;
			}
			return traits_type::eof();
		}
	private:
		std::vector<char> &vec;
		char* last = 0;
		char* first = 0;
	};

	class IoHelper {
		template <typename ...Args>
		friend IoHelper& operator<<(IoHelper &os, const std::tuple<Args...>& value);
		template <typename T>
		friend IoHelper& operator<<(IoHelper &os, const T& tuple);
		template <typename ...Args>
		friend IoHelper& operator>>(IoHelper &is, std::tuple<Args...>& tuple);
		template <typename T>
		friend IoHelper& operator>>(IoHelper &is, T& value);
	public:
		IoHelper(std::streambuf *buf, bool _convert = false) :ios(buf), convert(_convert) {}
		IoHelper(DataVec &vec, bool _convert = false) :ios(makeBuffer(vec)), convert(_convert) {}

		template <typename T>
		void write(const T& value, size_t bytes = sizeof(T));

		template <typename T>
		void read(T& value, size_t bytes = sizeof(T));

		template <typename T>
		T getValue(size_t count = sizeof(T));

		template <typename ...Args>
		void getValues(Args& ...args);

		template <typename ...Types, typename ...Args>
		void getCastedValues(Args& ...args);

		template <typename ...OutputTypes, typename ...TnSs>
		std::tuple<OutputTypes...> getTuple(TnSs ...tnss) {
			return std::tuple<OutputTypes...>{ static_cast<OutputTypes>(getSomeValue(tnss))... };
		}

		template <typename ...Args>
		void putValues(const Args& ...args);

		template <typename ...Types, typename ...Args>
		void putCastedValues(const Args& ...args);

	private:
		template <typename O, typename T>
		typename std::enable_if<!std::is_same<O, T>::value, void>::type
			getSomeValue(T& value) {
			O temp;
			read(temp);
			value = static_cast<T>(temp);
		}
		template <typename O, typename T>
		typename std::enable_if<std::is_same<O, T>::value, void>::type
			getSomeValue(T& value) {
			read(value);
		}
		template <typename T>
		static T parseType(size_t size) {
			return T();
		}
		template <>
		static DataVec parseType<DataVec>(size_t size) {
			return DataVec(size);
		}
		template <typename T>
		typename TnS<T>::type getSomeValue(TnS<T> tns) {
			typename TnS<T>::type value = parseType<typename TnS<T>::type>(tns.size);
			read(value);
			return value;
		}
		DataVecBuf* makeBuffer(DataVec &vec) {
			m_buf = std::make_shared<DataVecBuf>(vec);
			return m_buf.get();
		}
		std::shared_ptr<DataVecBuf> m_buf;
		std::iostream ios;
		bool convert;
	};

	template<typename T>
	inline void IoHelper::write(const T & value, size_t bytes)
	{
		if (convert && std::is_integral<T>::value) {
			T temp = value;
			temp = boost::endian::native_to_big(temp);
			ios.write(reinterpret_cast<const char*>(&temp), sizeof(T));
		}
		else {
			ios.write(reinterpret_cast<const char*>(&value), sizeof(T));
		}
	}

	template<>
	inline void IoHelper::write<std::vector<char>>(const std::vector<char> & value, size_t)
	{
		ios.write(value.data(), value.size());
	}

	template<typename T>
	inline void IoHelper::read(T & value, size_t bytes)
	{
		ios.read(reinterpret_cast<char*>(&value), bytes);
		if (convert && std::is_integral<T>::value) {
			boost::endian::big_to_native_inplace(value);
		}
	}

	template<>
	inline void IoHelper::read(std::vector<char> & value, size_t bytes)
	{
		ios.read(value.data(), value.size());
	}

	template<typename T>
	inline T IoHelper::getValue(size_t count)
	{
		T value;
		read(value);
		return value;
	}

	template <>
	inline std::vector<char> IoHelper::getValue<std::vector<char>>(size_t count) {
		std::vector<char> value(count);
		read(value);
		return value;
	}

	template<typename ...Args>
	inline void IoHelper::getValues(Args & ...args)
	{
		std::initializer_list<int>{
			([this](auto &value) {
				read(value);
			}(args), 0)...
		};
	}

	template<typename ...Types, typename ...Args>
	inline void IoHelper::getCastedValues(Args & ...args)
	{
		std::initializer_list<int>{
			([this](auto& value) {
				getSomeValue<Types>(value);
			}(args), 0)...
		};
	}

	template<typename ...Args>
	inline void IoHelper::putValues(const Args & ...args)
	{
		std::initializer_list<int>{
			([this](const auto &value) {
				write(value);
			}(args), 0)...
		};
	}

	template<typename ...Types, typename ...Args>
	inline void IoHelper::putCastedValues(const Args & ...args)
	{
		std::initializer_list<int>{
			([this](const auto &value) {
				write(static_cast<Types>(value));
			}(args), 0)...
		};
	}

	template<typename ...Args>
	IoHelper & operator<<(IoHelper & os, const std::tuple<Args...>& tuple)
	{
		for_each(tuple, [&os](const auto& v) {
			os.write(v);
		}, std::make_index_sequence<sizeof...(Args)>());
		return os;
	}
	template<typename T>
	IoHelper & operator<<(IoHelper & os, const T & value)
	{
		os.write(value);
		return os;
	}
	template<typename ...Args>
	IoHelper & operator>>(IoHelper & is, std::tuple<Args...>& tuple)
	{
		for_each(tuple, [&is](auto& v) {
			is.read(v);
		}, std::make_index_sequence<sizeof...(Args)>());
		return is;
	}
	template<typename T>
	IoHelper & operator>>(IoHelper & is, T & value)
	{
		is.read(value);
		return is;
	}
}

#endif // MYPROXYIOHELPER
