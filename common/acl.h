#pragma once

#include "type.h"

namespace common::acl
{

class tree_value_t
{
public:
	tree_value_t() = default;

	constexpr bool operator<(const tree_value_t& second) const
	{
		return id < second.id;
	}

	[[nodiscard]] bool is_empty() const
	{
		return !id;
	}

	[[nodiscard]] uint32_t get_group_id() const
	{
		return id;
	}

	void set_group_id(const uint32_t group_id)
	{
		id = group_id;
	}

	[[nodiscard]] bool is_chunk_id() const
	{
		return id & 0x80000000u;
	}

	[[nodiscard]] uint32_t get_chunk_id() const
	{
		return id ^ 0x80000000u;
	}

	void set_chunk_id(const uint32_t chunk_id)
	{
		id = chunk_id ^ 0x80000000u;
	}

protected:
	uint32_t id{}; ///< stored group_id or chunk_id
};

template<unsigned int bits = 8>
class tree_chunk_t
{
public:
	tree_chunk_t() = default;

	SERIALIZABLE(values);

	uint8_t is_multirefs{};
	tree_value_t values[1u << bits];
};

using tree_chunk_8bit_t = tree_chunk_t<8>;

struct transport_key_t
{
	constexpr bool operator<(const transport_key_t& second) const
	{
		return std::tie(network_id,
		                protocol,
		                group1,
		                group2,
		                group3,
		                network_flags) <
		       std::tie(second.network_id,
		                second.protocol,
		                second.group1,
		                second.group2,
		                second.group3,
		                second.network_flags);
	}

	tAclGroupId network_id : 32;
	tAclGroupId protocol : 16;
	tAclGroupId group1 : 16;
	tAclGroupId group2 : 16;
	tAclGroupId group3 : 8;
	tAclGroupId network_flags : 8;
};

struct total_key_t
{
	bool operator==(const total_key_t& second) const
	{
		return std::tie(acl_id, transport_id) ==
		       std::tie(second.acl_id, second.transport_id);
	}

	bool operator!=(const total_key_t& second) const
	{
		return !(*this == second);
	}

	tAclGroupId acl_id;
	tAclGroupId transport_id;
};

template<typename type_t>
class range_t
{
public:
	range_t() :
	        from_to{0, 0}
	{
	}

	range_t(const type_t value) :
	        from_to{value, value}
	{
	}

	range_t(const type_t from,
	        const type_t to) :
	        from_to{from, to}
	{
	}

	constexpr bool operator<(const range_t<type_t>& second) const
	{
		return from_to < second.from_to;
	}

public:
	type_t from() const
	{
		return std::get<0>(from_to);
	}

	type_t to() const
	{
		return std::get<1>(from_to);
	}

	SERIALIZABLE(from_to);

public:
	std::tuple<type_t, type_t> from_to;
};

template<typename type_t>
class ranges_t
{
public:
	constexpr bool operator<(const ranges_t<type_t>& second) const
	{
		return vector < second.vector;
	}

public:
	SERIALIZABLE(vector);

	void insert_any()
	{
		vector.emplace_back(0u, (1u << (8 * sizeof(type_t))) - 1u);
	}

public:
	std::vector<range_t<type_t>> vector;
};

using ranges_uint8_t = ranges_t<uint8_t>;
using ranges_uint16_t = ranges_t<uint16_t>;

}

template<>
struct std::hash<common::acl::total_key_t>
{
	std::size_t operator()(const common::acl::total_key_t& key) const noexcept
	{
		std::size_t res = 0;
		common::hash_combine(res, key.acl_id);
		common::hash_combine(res, key.transport_id);
		return res;
	}
};
