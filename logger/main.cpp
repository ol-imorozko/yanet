#include <csignal>
#include <fstream>
#include <systemd/sd-daemon.h>
#include <thread>

#include <iostream>
#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_version.h>

#include "common/define.h"
#include "common/icontrolplane.h"
#include "common/idataplane.h"
#include "common/type.h"

#include "dataplane/samples.h"

common::log::LogPriority common::log::logPriority = common::log::TLOG_INFO;

void handleSignal(int signalType)
{
	if (signalType == SIGINT)
	{
		YANET_LOG_INFO("signal: SIGINT\n");
		/// @todo: stop
	}
	else if (signalType == SIGPIPE)
	{
		YANET_LOG_INFO("signal: SIGPIPE\n");
	}
}

std::vector<rte_ring*> rings;
rte_mempool* mempool;
tCoreId loggerCoreId = 0;
int sleepMicroseconds = 1000;

int initLogger()
{
	interface::dataPlane dataplane;
	auto response = dataplane.getConfig();
	auto& workers = std::get<1>(response);

	for (auto& [core, workers_vector] : workers)
	{
		GCC_BUG_UNUSED(workers_vector);
		auto ring = rte_ring_lookup(("r_log_" + std::to_string(core)).c_str());
		if (ring != nullptr)
		{
			YANET_LOG_DEBUG("found log ring on #%u core\n", core);

			rings.push_back(ring);
		}
	}
	if (rings.size() == 0)
	{
		YANET_LOG_ERROR("can not find log rings\n");
		return 4;
	}

	if (loggerCoreId == 0 || loggerCoreId >= std::thread::hardware_concurrency())
	{
		YANET_LOG_ERROR("can not find free core for logger\n");
		return 5;
	}

	mempool = rte_mempool_lookup("log");
	if (mempool == nullptr)
	{
		YANET_LOG_ERROR("can not find log mempool\n");
		return 6;
	}

	YANET_LOG_DEBUG("found %lu log rings\n", rings.size());
	YANET_LOG_DEBUG("using core #%u for logger\n", loggerCoreId);

	return 0;
}

int runLogger()
{
	YANET_LOG_DEBUG("started logger on #%u core\n", rte_lcore_id());

	if (rte_lcore_id() != loggerCoreId)
	{
		YANET_LOG_ERROR("started logger on wrong core (contradicts #%u from config)\n", loggerCoreId);
		return 7;
	}

	interface::controlPlane controlplane;

	constexpr uint32_t size = 1024;
	std::array<samples::sample_t*, size> samples;

	std::map<uint32_t, common::icp::getAclConfig::response> configs;

	common::icp::getAclConfig::response* aclConfig = nullptr;
	for (;;)
	{
		uint32_t packets = 0;

		for (auto ring : rings)
		{
			auto count = rte_ring_dequeue_burst(ring, (void**)&samples, size, nullptr);
			packets += count;

			for (uint32_t i = 0; i < count; i++)
			{
				samples::sample_t* sample = samples[i];

				common::ip_address_t src_addr = sample->is_ipv6 ? common::ip_address_t(sample->ipv6_src_addr.bytes) : common::ip_address_t(rte_be_to_cpu_32(sample->ipv4_src_addr.address));
				common::ip_address_t dst_addr = sample->is_ipv6 ? common::ip_address_t(sample->ipv6_dst_addr.bytes) : common::ip_address_t(rte_be_to_cpu_32(sample->ipv4_dst_addr.address));

				if (aclConfig == nullptr || sample->serial != std::get<0>(*aclConfig))
				{
					auto it = configs.lower_bound(sample->serial);
					if (it == configs.end() || it->first != sample->serial)
					{
						auto conf = controlplane.getAclConfig(sample->serial);
						if (std::get<0>(conf) == sample->serial)
						{
							YANET_LOG_DEBUG("got acl config for serial %d\n", sample->serial);
							if (configs.size() > YANET_CONFIG_CONFIG_CACHE_SIZE)
							{
								if (it == configs.end())
								{
									it = configs.begin();
								}
								configs.erase(it);
							}
							configs[sample->serial] = conf;
							aclConfig = &configs[sample->serial];
						}
						else
						{
							YANET_LOG_WARNING("can not get acl config for serial %d\n", sample->serial);
							aclConfig = nullptr;
						}
					}
					else
					{
						aclConfig = &it->second;
					}
				}

				auto direction = true;
				auto iface = std::string("unknown_") + std::to_string(sample->acl_id);
				auto rule_ids = std::string();

				if (aclConfig != nullptr)
				{
					auto& [serial, ifaces, rules] = *aclConfig;
					GCC_BUG_UNUSED(serial);

					auto it = ifaces.find(sample->acl_id);
					if (it != ifaces.end())
					{
						direction = std::get<0>(*it->second.begin());
						iface = std::get<1>(*it->second.begin());
					}
					if (sample->counter_id < rules.size() && !rules[sample->counter_id].empty())
					{
						auto& v = rules[sample->counter_id];
						rule_ids = std::accumulate(v.begin() + 1, v.end(), std::to_string(v[0]), [](const std::string& a, int b) {
							return a + ',' + std::to_string(b);
						});
					}
				}

				std::cout << "{"
				          << R"("action":")" << common::globalBase::eFlowType_toString(sample->action) << "\","
				          << "\"rule_ids\":[" << rule_ids << "],"
				          << "\"direction\":" << (direction ? "\"in\"" : "\"out\"") << ","
				          << R"("iface":")" << iface << "\","
				          << "\"proto\":" << (int)sample->proto << ","
				          << R"("src_addr":")" << src_addr.toString() << "\","
				          << "\"src_port\":" << sample->src_port << ","
				          << R"("dst_addr":")" << dst_addr.toString() << "\","
				          << "\"dst_port\":" << sample->dst_port << "}\n";

				rte_mempool_put(mempool, sample);
			}
		}

		if (packets == 0)
		{
			std::this_thread::sleep_for(std::chrono::microseconds{sleepMicroseconds});
		}
	}

	return 0;
}

int loadConfig(const std::string& path)
{
	if (path.empty())
	{
		return 1;
	}

	std::ifstream fromFileStream(path);
	if (!fromFileStream.is_open())
	{
		YANET_LOG_ERROR("can't open file '%s'\n", path.data());
		return 1;
	}

	nlohmann::json rootJson = nlohmann::json::parse(fromFileStream, nullptr, false);
	if (rootJson.is_discarded())
	{
		YANET_LOG_ERROR("invalid json format\n");
		return 1;
	}

	auto v = rootJson.find("loggerCoreId");
	if (v != rootJson.end())
	{
		loggerCoreId = v.value();
	}
	else
	{
		return 1;
	}

	v = rootJson.find("sleepMicroseconds");
	if (v != rootJson.end())
	{
		sleepMicroseconds = v.value();
	}

	return 0;
}

int main(int argc, char** argv)
{
	int config = argc;
	for (int i = 1; i < argc; i++)
	{
		std::string_view arg{argv[i]};
		if (arg == "-d")
		{
			common::log::logPriority = common::log::TLOG_DEBUG;
		}
		else if (arg == "-c")
		{
			config = i + 1;
		}
	}

	if (config >= argc)
	{
		std::cout << "usage: " << argv[0] << " [-d] -c <logger.conf>" << std::endl;
		return 1;
	}

	int ret = loadConfig(argv[config]);
	if (ret != 0)
	{
		return ret;
	}

	std::vector<std::string> args;
	args.push_back(argv[0]);
	args.emplace_back("--proc-type=secondary");

	std::string filePrefix = "--file-prefix=";
	if (const char* pointer = std::getenv("YANET_FILEPREFIX"))
	{
		filePrefix += pointer;
	}
	else if (const char* pointer = std::getenv("YANET_PREFIX"))
	{
		filePrefix += pointer;
	}

	if (filePrefix.size() > std::string("--file-prefix=").size())
	{
		args.push_back(filePrefix);
	}

#if (RTE_VER_YEAR < 20) || (RTE_VER_YEAR == 20 && RTE_VER_MONT < 11)
	const std::string masterLcore = "--master-lcore";
#else
	const std::string masterLcore = "--main-lcore";
#endif

	std::string masterLcoreId = std::to_string(loggerCoreId);
	args.push_back(masterLcore);
	args.push_back(masterLcoreId);

	YANET_LOG_DEBUG("eal args:\n");
	for (const auto& arg : args)
	{
		YANET_LOG_DEBUG("%s\n", arg.c_str());
	}

	// Use std::vector<char*> and copy the data into it for passing to rte_eal_init
	std::vector<char*> c_args;
	for (auto& arg : args)
	{
		c_args.push_back(const_cast<char*>(arg.c_str()));
	}

	ret = rte_eal_init(static_cast<int>(c_args.size()), c_args.data());
	if (ret < 0)
	{
		YANET_LOG_ERROR("rte_eal_init() = %d\n", ret);
		return 2;
	}

	if (std::signal(SIGPIPE, handleSignal) == SIG_ERR)
	{
		return 3;
	}

	ret = initLogger();
	if (ret != 0)
	{
		return ret;
	}

	sd_notify(0, "READY=1");

	return runLogger();
}
