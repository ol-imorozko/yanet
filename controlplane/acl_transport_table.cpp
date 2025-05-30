#include "acl_transport_table.h"
#include "acl_compiler.h"

using namespace acl::compiler;

transport_table_t::transport_table_t(acl::compiler_t* compiler,
                                     const unsigned int threads_count) :
        compiler(compiler),
        threads_count(threads_count)
{
	clear();
}

void transport_table_t::clear()
{
	threads.clear();
	filters.clear();
	filter_ids.clear();
}

unsigned int transport_table_t::collect(const unsigned int rule_id, const filter& filter)
{
	auto it = filter_ids.find(filter);
	if (it == filter_ids.end())
	{
		filters.emplace_back(filter);
		it = filter_ids.emplace_hint(it, filter, filter_ids.size());
	}

	return it->second;
}

void transport_table_t::prepare()
{
	threads_count = std::min((unsigned int)compiler->transport.layers.size(), threads_count);

	for (unsigned int thread_id = 0;
	     thread_id < threads_count;
	     thread_id++)
	{
		threads.emplace_back(this,
		                     thread_id,
		                     threads_count);
	}
}

void transport_table_t::compile()
{
	for (auto& thread : threads)
	{
		thread.start();
	}
}

void transport_table_t::populate()
{
	for (auto& thread : threads)
	{
		thread.join();
	}
}

void transport_table_t::remap()
{
}

transport_table::thread_t::thread_t(transport_table_t* transport_table,
                                    const unsigned int thread_id,
                                    const unsigned int threads_count) :
        transport_table(transport_table),
        thread_id(thread_id),
        threads_count(threads_count), group_id(1 + thread_id)
{
}

void transport_table::thread_t::start()
{
	thread = std::thread([this]() {
		try
		{
			prepare();
			compile();
			populate();
			result();
		}
		catch (...)
		{
			YANET_LOG_ERROR("exception in thread\n");
			exception = std::current_exception();
		}
	});
}

void transport_table::thread_t::join()
{
	if (thread.joinable())
	{
		thread.join();
	}

	if (exception)
	{
		std::rethrow_exception(*exception);
	}
}

void transport_table::thread_t::prepare()
{
	layers.resize(transport_table->compiler->transport.layers.size());

	for (unsigned int layer_id = thread_id;
	     layer_id < transport_table->compiler->transport.layers.size();
	     layer_id += threads_count)
	{
		const auto& transport_layer = transport_table->compiler->transport.layers[layer_id];
		auto& layer = layers[layer_id];

		unsigned int group1_size = transport_layer.tcp_source.group_id;
		group1_size = std::max(group1_size, transport_layer.udp_source.group_id);
		group1_size = std::max(group1_size, transport_layer.icmp_type_code.group_id);

		unsigned int group2_size = transport_layer.tcp_destination.group_id;
		group2_size = std::max(group2_size, transport_layer.udp_destination.group_id);
		group2_size = std::max(group2_size, transport_layer.icmp_identifier.group_id);

		unsigned int group3_size = transport_layer.tcp_flags.group_id;

		layer.table.prepare(transport_table->compiler->network_flags.group_id - 1, /// id always start with 1
		                    transport_layer.protocol.group_id - 1, /// id always start with 1
		                    group1_size,
		                    group2_size,
		                    group3_size,
		                    transport_layer.network_table_group_ids_vec.size());

		/// prepare remap vector for compress network_table_group_ids
		layer.prepare_remap_map(transport_layer.network_table_group_ids_vec,
		                        transport_table->compiler->transport_layers_shift);
	}
}

void transport_table::thread_t::compile()
{
	DimensionArray table_indexes;
	table_indexes.fill(0);

	for (auto [network_table_filter_id, network_flags_filter_id, transport_filter_id] : transport_table->filters)
	{
		remap_group_ids.clear();
		initial_group_id = group_id;

		const auto& network_table_group_ids_orig = transport_table->compiler->network_table.filter_id_group_ids[network_table_filter_id];
		const auto& network_flags_group_ids = transport_table->compiler->network_flags.filter_id_group_ids[network_flags_filter_id];

		std::vector<tAclGroupId> network_table_group_ids;
		std::vector<tAclGroupId> network_table_group_ids_curr;
		std::vector<tAclGroupId> network_table_group_ids_next(network_table_group_ids_orig.begin(), network_table_group_ids_orig.end());

		for (unsigned int layer_id = thread_id;
		     layer_id < transport_table->compiler->transport.layers.size();
		     layer_id += threads_count)
		{
			const auto& transport_layer = transport_table->compiler->transport.layers[layer_id];
			auto& layer = layers[layer_id];

			if (!transport_layer.filter_ids_set.count(transport_filter_id))
			{
				continue;
			}

			if (network_table_group_ids_next.empty())
			{
				break;
			}

			network_table_group_ids.swap(network_table_group_ids_next);
			network_table_group_ids_curr.clear();
			network_table_group_ids_next.clear();

			for (const auto network_table_group_id : network_table_group_ids)
			{
				if (transport_layer.network_table_group_ids_set.count(network_table_group_id))
				{
					network_table_group_ids_curr.emplace_back(network_table_group_id);
				}
				else
				{
					network_table_group_ids_next.emplace_back(network_table_group_id);
				}
			}

			const auto& protocol_group_ids = transport_layer.protocol.filter_id_group_ids[transport_layer.protocol_id[transport_filter_id]];
			const auto& tcp_source_group_ids = transport_layer.tcp_source.filter_id_group_ids[transport_layer.tcp_source_id[transport_filter_id]];
			const auto& tcp_destination_group_ids = transport_layer.tcp_destination.filter_id_group_ids[transport_layer.tcp_destination_id[transport_filter_id]];
			const auto& tcp_flags_group_ids = transport_layer.tcp_flags.filter_id_group_ids[transport_layer.tcp_flags_id[transport_filter_id]];
			const auto& udp_source_group_ids = transport_layer.udp_source.filter_id_group_ids[transport_layer.udp_source_id[transport_filter_id]];
			const auto& udp_destination_group_ids = transport_layer.udp_destination.filter_id_group_ids[transport_layer.udp_destination_id[transport_filter_id]];
			const auto& icmpv4_type_code_group_ids = transport_layer.icmp_type_code.filter_id_group_ids[transport_layer.icmpv4_type_code_id[transport_filter_id]];
			const auto& icmpv4_identifier_group_ids = transport_layer.icmp_identifier.filter_id_group_ids[transport_layer.icmpv4_identifier_id[transport_filter_id]];
			const auto& icmpv6_type_code_group_ids = transport_layer.icmp_type_code.filter_id_group_ids[transport_layer.icmpv6_type_code_id[transport_filter_id]];
			const auto& icmpv6_identifier_group_ids = transport_layer.icmp_identifier.filter_id_group_ids[transport_layer.icmpv6_identifier_id[transport_filter_id]];

			for (const auto& protocol_group_id : protocol_group_ids)
			{
				/// @todo: skip tcp,udp,icmp

				table_indexes[1] = protocol_group_id - 1; /// id always start with 1
				table_indexes[2] = 0;
				table_indexes[3] = 0;
				table_indexes[4] = 0;

				for (const auto network_flags_group_id : network_flags_group_ids)
				{
					table_indexes[0] = network_flags_group_id - 1; /// id always start with 1
					for (unsigned int network_table_group_id : network_table_group_ids_curr)
					{
						table_indexes[5] = layer.lookup_remap_map(
						        network_table_group_id,
						        transport_table->compiler->transport_layers_shift);

						table_insert(layer, table_indexes);
					}
				}
			}

			/// @todo: check if not fragment

			/// tcp
			{
				table_indexes[1] = transport_layer.protocol.get(IPPROTO_TCP) - 1; /// id always start with 1

				for (const auto& tcp_source_id : tcp_source_group_ids)
				{
					table_indexes[2] = tcp_source_id;
					for (const auto& tcp_destination_id : tcp_destination_group_ids)
					{
						table_indexes[3] = tcp_destination_id;
						for (const auto& tcp_flags_id : tcp_flags_group_ids)
						{
							table_indexes[4] = tcp_flags_id;
							for (const auto network_flags_group_id : network_flags_group_ids)
							{
								table_indexes[0] = network_flags_group_id - 1; /// id always start with 1
								for (unsigned int network_table_group_id : network_table_group_ids_curr)
								{
									table_indexes[5] = layer.lookup_remap_map(
									        network_table_group_id,
									        transport_table->compiler->transport_layers_shift);

									table_insert(layer, table_indexes);
								}
							}
						}
					}
				}
			}

			/// udp
			{
				table_indexes[1] = transport_layer.protocol.get(IPPROTO_UDP) - 1; /// id always start with 1
				table_indexes[4] = 0;

				for (const auto& udp_source_id : udp_source_group_ids)
				{
					table_indexes[2] = udp_source_id;
					for (const auto& udp_destination_id : udp_destination_group_ids)
					{
						table_indexes[3] = udp_destination_id;
						for (const auto network_flags_group_id : network_flags_group_ids)
						{
							table_indexes[0] = network_flags_group_id - 1; /// id always start with 1
							for (unsigned int network_table_group_id : network_table_group_ids_curr)
							{
								table_indexes[5] = layer.lookup_remap_map(
								        network_table_group_id,
								        transport_table->compiler->transport_layers_shift);

								table_insert(layer, table_indexes);
							}
						}
					}
				}
			}

			/// icmp
			{
				table_indexes[1] = transport_layer.protocol.get(IPPROTO_ICMP) - 1; /// id always start with 1
				table_indexes[4] = 0;

				for (const auto& icmp_type_code_id : icmpv4_type_code_group_ids)
				{
					table_indexes[2] = icmp_type_code_id;
					for (const auto& icmp_identifier_id : icmpv4_identifier_group_ids)
					{
						table_indexes[3] = icmp_identifier_id;
						for (const auto network_flags_group_id : network_flags_group_ids)
						{
							table_indexes[0] = network_flags_group_id - 1; /// id always start with 1
							for (unsigned int network_table_group_id : network_table_group_ids_curr)
							{
								table_indexes[5] = layer.lookup_remap_map(
								        network_table_group_id,
								        transport_table->compiler->transport_layers_shift);

								table_insert(layer, table_indexes);
							}
						}
					}
				}
			}

			/// icmp_v6
			{
				table_indexes[1] = transport_layer.protocol.get(IPPROTO_ICMPV6) - 1; /// id always start with 1
				table_indexes[4] = 0;

				for (const auto& icmp_type_code_id : icmpv6_type_code_group_ids)
				{
					table_indexes[2] = icmp_type_code_id;
					for (const auto& icmp_identifier_id : icmpv6_identifier_group_ids)
					{
						table_indexes[3] = icmp_identifier_id;
						for (const auto network_flags_group_id : network_flags_group_ids)
						{
							table_indexes[0] = network_flags_group_id - 1; /// id always start with 1
							for (unsigned int network_table_group_id : network_table_group_ids_curr)
							{
								table_indexes[5] = layer.lookup_remap_map(
								        network_table_group_id,
								        transport_table->compiler->transport_layers_shift);

								table_insert(layer, table_indexes);
							}
						}
					}
				}
			}
		}
	}
}

void transport_table::thread_t::populate()
{
	DimensionArray table_indexes;
	table_indexes.fill(0);

	for (unsigned int filter_id = 0;
	     filter_id < transport_table->filters.size();
	     filter_id++)
	{
		const auto& [network_table_filter_id, network_flags_filter_id, transport_filter_id] = transport_table->filters[filter_id];
		const auto& network_table_group_ids_orig = transport_table->compiler->network_table.filter_id_group_ids[network_table_filter_id];
		const auto& network_flags_group_ids = transport_table->compiler->network_flags.filter_id_group_ids[network_flags_filter_id];

		std::vector<tAclGroupId> network_table_group_ids;
		std::vector<tAclGroupId> network_table_group_ids_curr;
		std::vector<tAclGroupId> network_table_group_ids_next(network_table_group_ids_orig.begin(), network_table_group_ids_orig.end());

		for (unsigned int layer_id = thread_id;
		     layer_id < transport_table->compiler->transport.layers.size();
		     layer_id += threads_count)
		{
			const auto& transport_layer = transport_table->compiler->transport.layers[layer_id];
			auto& layer = layers[layer_id];

			if (!transport_layer.filter_ids_set.count(transport_filter_id))
			{
				continue;
			}

			if (network_table_group_ids_next.empty())
			{
				break;
			}

			network_table_group_ids.swap(network_table_group_ids_next);
			network_table_group_ids_curr.clear();
			network_table_group_ids_next.clear();

			for (const auto network_table_group_id : network_table_group_ids)
			{
				if (transport_layer.network_table_group_ids_set.count(network_table_group_id))
				{
					network_table_group_ids_curr.emplace_back(network_table_group_id);
				}
				else
				{
					network_table_group_ids_next.emplace_back(network_table_group_id);
				}
			}

			const auto& protocol_group_ids = transport_layer.protocol.filter_id_group_ids[transport_layer.protocol_id[transport_filter_id]];
			const auto& tcp_source_group_ids = transport_layer.tcp_source.filter_id_group_ids[transport_layer.tcp_source_id[transport_filter_id]];
			const auto& tcp_destination_group_ids = transport_layer.tcp_destination.filter_id_group_ids[transport_layer.tcp_destination_id[transport_filter_id]];
			const auto& tcp_flags_group_ids = transport_layer.tcp_flags.filter_id_group_ids[transport_layer.tcp_flags_id[transport_filter_id]];
			const auto& udp_source_group_ids = transport_layer.udp_source.filter_id_group_ids[transport_layer.udp_source_id[transport_filter_id]];
			const auto& udp_destination_group_ids = transport_layer.udp_destination.filter_id_group_ids[transport_layer.udp_destination_id[transport_filter_id]];
			const auto& icmpv4_type_code_group_ids = transport_layer.icmp_type_code.filter_id_group_ids[transport_layer.icmpv4_type_code_id[transport_filter_id]];
			const auto& icmpv4_identifier_group_ids = transport_layer.icmp_identifier.filter_id_group_ids[transport_layer.icmpv4_identifier_id[transport_filter_id]];
			const auto& icmpv6_type_code_group_ids = transport_layer.icmp_type_code.filter_id_group_ids[transport_layer.icmpv6_type_code_id[transport_filter_id]];
			const auto& icmpv6_identifier_group_ids = transport_layer.icmp_identifier.filter_id_group_ids[transport_layer.icmpv6_identifier_id[transport_filter_id]];

			for (const auto& protocol_group_id : protocol_group_ids)
			{
				/// @todo: skip tcp,udp,icmp

				table_indexes[1] = protocol_group_id - 1; /// id always start with 1
				table_indexes[2] = 0;
				table_indexes[3] = 0;
				table_indexes[4] = 0;

				for (const auto network_flags_group_id : network_flags_group_ids)
				{
					table_indexes[0] = network_flags_group_id - 1; /// id always start with 1
					for (unsigned int network_table_group_id : network_table_group_ids_curr)
					{
						table_indexes[5] = layer.lookup_remap_map(
						        network_table_group_id,
						        transport_table->compiler->transport_layers_shift);

						table_get(layer, table_indexes, filter_id);
					}
				}
			}

			/// @todo: check if not fragment

			/// tcp
			{
				table_indexes[1] = transport_layer.protocol.get(IPPROTO_TCP) - 1; /// id always start with 1

				for (const auto& tcp_source_id : tcp_source_group_ids)
				{
					table_indexes[2] = tcp_source_id;
					for (const auto& tcp_destination_id : tcp_destination_group_ids)
					{
						table_indexes[3] = tcp_destination_id;
						for (const auto& tcp_flags_id : tcp_flags_group_ids)
						{
							table_indexes[4] = tcp_flags_id;
							for (const auto network_flags_group_id : network_flags_group_ids)
							{
								table_indexes[0] = network_flags_group_id - 1; /// id always start with 1
								for (unsigned int network_table_group_id : network_table_group_ids_curr)
								{
									table_indexes[5] = layer.lookup_remap_map(
									        network_table_group_id,
									        transport_table->compiler->transport_layers_shift);

									table_get(layer, table_indexes, filter_id);
								}
							}
						}
					}
				}
			}

			/// udp
			{
				table_indexes[1] = transport_layer.protocol.get(IPPROTO_UDP) - 1; /// id always start with 1
				table_indexes[4] = 0;

				for (const auto& udp_source_id : udp_source_group_ids)
				{
					table_indexes[2] = udp_source_id;
					for (const auto& udp_destination_id : udp_destination_group_ids)
					{
						table_indexes[3] = udp_destination_id;
						for (const auto network_flags_group_id : network_flags_group_ids)
						{
							table_indexes[0] = network_flags_group_id - 1; /// id always start with 1
							for (unsigned int network_table_group_id : network_table_group_ids_curr)
							{
								table_indexes[5] = layer.lookup_remap_map(
								        network_table_group_id,
								        transport_table->compiler->transport_layers_shift);

								table_get(layer, table_indexes, filter_id);
							}
						}
					}
				}
			}

			/// icmp
			{
				table_indexes[1] = transport_layer.protocol.get(IPPROTO_ICMP) - 1; /// id always start with 1
				table_indexes[4] = 0;

				for (const auto& icmp_type_code_id : icmpv4_type_code_group_ids)
				{
					table_indexes[2] = icmp_type_code_id;
					for (const auto& icmp_identifier_id : icmpv4_identifier_group_ids)
					{
						table_indexes[3] = icmp_identifier_id;
						for (const auto network_flags_group_id : network_flags_group_ids)
						{
							table_indexes[0] = network_flags_group_id - 1; /// id always start with 1
							for (unsigned int network_table_group_id : network_table_group_ids_curr)
							{
								table_indexes[5] = layer.lookup_remap_map(
								        network_table_group_id,
								        transport_table->compiler->transport_layers_shift);

								table_get(layer, table_indexes, filter_id);
							}
						}
					}
				}
			}

			/// icmp_v6
			{
				table_indexes[1] = transport_layer.protocol.get(IPPROTO_ICMPV6) - 1; /// id always start with 1
				table_indexes[4] = 0;

				for (const auto& icmp_type_code_id : icmpv6_type_code_group_ids)
				{
					table_indexes[2] = icmp_type_code_id;
					for (const auto& icmp_identifier_id : icmpv6_identifier_group_ids)
					{
						table_indexes[3] = icmp_identifier_id;
						for (const auto network_flags_group_id : network_flags_group_ids)
						{
							table_indexes[0] = network_flags_group_id - 1; /// id always start with 1
							for (unsigned int network_table_group_id : network_table_group_ids_curr)
							{
								table_indexes[5] = layer.lookup_remap_map(
								        network_table_group_id,
								        transport_table->compiler->transport_layers_shift);

								table_get(layer, table_indexes, filter_id);
							}
						}
					}
				}
			}
		}
	}
}

void transport_table::thread_t::result()
{
	for (unsigned int layer_id = thread_id;
	     layer_id < transport_table->compiler->transport.layers.size();
	     layer_id += threads_count)
	{
		const auto& transport_layer = transport_table->compiler->transport.layers[layer_id];
		auto& layer = layers[layer_id];

		acl_transport_table.reserve(acl_transport_table.size() + layer.table.size());

		layer.table.for_each([&](const DimensionArray& keys,
		                         const unsigned int value) {
			common::acl::transport_key_t key;
			key.network_flags = keys[0] + 1; /// id always start with 1
			key.protocol = keys[1] + 1; /// id always start with 1
			key.group1 = keys[2];
			key.group2 = keys[3];
			key.group3 = keys[4];
			key.network_id = transport_layer.network_table_group_ids_vec[keys[5]];
			acl_transport_table.emplace_back(key, value);
		});

		layer.table.clear();
	}
}

void transport_table::thread_t::table_insert(transport_table::layer_t& layer,
                                             const DimensionArray& keys)
{
	auto& value = layer.table(keys);

	if (value >= initial_group_id)
		return;

	auto it = remap_group_ids.find(value);
	if (it == remap_group_ids.end()) ///< check: don't override self rule
	{
		remap_group_ids.emplace(value, group_id);
		value = group_id;
		group_id += threads_count;
	}
	else
	{
		value = it->second;
	}
}

void transport_table::thread_t::table_get(const transport_table::layer_t& layer,
                                          const DimensionArray& keys,
                                          unsigned int filter_id)
{
	auto value = layer.table(keys);

	std::vector<unsigned int>& vec = group_id_filter_ids[value];
	if (std::find(vec.begin(), vec.end(), filter_id) == vec.end())
	{
		vec.push_back(filter_id);
	}
}
