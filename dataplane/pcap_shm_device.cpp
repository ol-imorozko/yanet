#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <pcap/pcap.h>
#include <vector>

#include "pcap_shm_device.h"

namespace pcpp
{

// Helper function for hex dumping memory
void HexDump(const void* data, size_t size, const std::string& prefix = "")
{
	const auto* bytes = static_cast<const uint8_t*>(data);
	std::cout << prefix << std::hex << std::setfill('0');
	for (size_t i = 0; i < size; ++i)
	{
		if (i % 16 == 0)
		{
			if (i != 0)
				std::cout << "\n";
			std::cout << prefix << "0x" << std::setw(4) << i << ": ";
		}
		std::cout << std::setw(2) << static_cast<int>(bytes[i]) << " ";
	}
	std::cout << std::dec << "\n";
}

bool PcapShmWriterDevice::RotateToNextSegment()
{
	std::cout << "Rotating to next segment. Current index: " << current_segment_index_
	          << ", total segments: " << pcap_files_ << "\n";

	current_segment_index_ = (current_segment_index_ + 1) % pcap_files_;
	FILE* file = segments_[current_segment_index_].file;

	std::cout << "New segment index: " << current_segment_index_
	          << ", file ptr: " << file << "\n";
	std::cout << "Seeking to position after pcap header (" << kPcapFileHeaderSize << " bytes)\n";

	bool result = (fseek(file, kPcapFileHeaderSize, SEEK_SET) == 0);
	std::cout << "Segment rotation " << (result ? "succeeded" : "failed") << "\n";
	return result;
}

bool PcapShmWriterDevice::FillSegments()
{
	std::cout << "Filling " << pcap_files_ << " segments in shared memory (total size: "
	          << shm_size_ << " bytes)\n";

	segments_.resize(pcap_files_);

	size_t base_size = shm_size_ / pcap_files_;
	size_t remainder = shm_size_ % pcap_files_;
	size_t offset = 0;

	std::cout << "Base segment size: " << base_size << " bytes, remainder: "
	          << remainder << " bytes\n";

	for (size_t i = 0; i < pcap_files_; ++i)
	{
		size_t segment_size = base_size + (i == pcap_files_ - 1 ? remainder : 0);
		segments_[i].start_ptr = static_cast<uint8_t*>(shm_ptr_) + offset;
		segments_[i].size = segment_size;

		std::cout << "\nInitializing segment " << i << ":\n";
		std::cout << "  Start ptr: " << segments_[i].start_ptr << "\n";
		std::cout << "  Size: " << segment_size << " bytes\n";
		std::cout << "  Offset: " << offset << "\n";

		offset += segment_size;

		FILE* file = fmemopen(segments_[i].start_ptr, segments_[i].size, "w+");
		if (!file)
		{
			std::cerr << "fmemopen failed for segment " << i << "\n";
			return false;
		}
		std::cout << "  File handle created: " << file << "\n";

		pcap_dumper_t* dumper = pcap_dump_fopen(m_PcapDescriptor.get(), file);
		if (!dumper)
		{
			std::cerr << "pcap_dump_fopen failed for segment " << i << "\n";
			fclose(file);
			return false;
		}
		std::cout << "  Pcap dumper created: " << dumper << "\n";

		segments_[i].file = file;
		segments_[i].dumper = dumper;
	}

	std::cout << "All segments initialized successfully\n";
	return true;
}

PcapShmWriterDevice::PcapShmWriterDevice(void* shm_ptr, size_t shm_size, size_t pcap_files, bool autotest, LinkLayerType link_layer_type, bool nanoseconds_precision) :
        IShmWriterDevice(shm_ptr, shm_size),
        link_layer_type_(link_layer_type),
        autotest_(autotest),
        pcap_files_(pcap_files),
        current_segment_index_(0)
{
	std::cout << (autotest_ ? "[AUTOTEST]:" : "[DATAPLANE]");
	std::cout << "Creating PcapShmWriterDevice:\n";
	std::cout << "  Shared memory ptr: " << shm_ptr << "\n";
	std::cout << "  Shared memory size: " << shm_size << " bytes\n";
	std::cout << "  Segment count: " << pcap_files << "\n";
	std::cout << "  Link layer type: " << link_layer_type << "\n";
	std::cout << "  Nanosecond precision: " << std::boolalpha << nanoseconds_precision << "\n";

#if defined(PCAP_TSTAMP_PRECISION_NANO)
	precision_ = nanoseconds_precision ? FileTimestampPrecision::Nanoseconds
	                                   : FileTimestampPrecision::Microseconds;
	std::cout << "Using timestamp precision: "
	          << (nanoseconds_precision ? "nanoseconds" : "microseconds") << "\n";
#else
	if (nanoseconds_precision)
	{
		std::cerr << "Nano precision requested but not supported by this build\n";
	}
	precision_ = FileTimestampPrecision::Microseconds;
	std::cout << "Using microsecond timestamp precision (default)\n";
#endif
}

PcapShmWriterDevice::~PcapShmWriterDevice()
{
	std::cout << (autotest_ ? "[AUTOTEST]:" : "[DATAPLANE]");
	std::cout << "Destroying PcapShmWriterDevice\n";
	PcapShmWriterDevice::close();
}

void PcapShmWriterDevice::DumpPcapFilesToDisk(std::string_view filename_prefix)
{
	std::cout << "Dumping pcap files to disk with prefix: " << filename_prefix << "\n";
	Flush();

	size_t file_index = 1;
	std::string filename;
	filename.reserve(filename_prefix.size() + 10);

	for (size_t i = 0; i < pcap_files_; ++i)
	{
		size_t segment_index = (current_segment_index_ + 1 + i) % pcap_files_;
		FILE* file = segments_[segment_index].file;

		std::cout << "\nProcessing segment " << segment_index << " (file: " << file << ")\n";

		if (file == nullptr)
		{
			std::cout << "  File pointer is null, skipping\n";
			continue;
		}

		long used = ftell(file);
		if (used < 0)
		{
			std::cerr << "ftell failed on segment " << i << "\n";
			continue;
		}
		std::cout << "  Bytes used in segment: " << used << "\n";

		if (static_cast<size_t>(used) <= kPcapFileHeaderSize)
		{
			std::cout << "  Only header present, no packets to dump\n";
			continue;
		}

		filename = filename_prefix;
		filename += std::to_string(file_index++) + ".pcap";
		std::cout << "  Writing to file: " << filename << "\n";

		std::ofstream output_file(filename, std::ios::binary);
		if (!output_file)
		{
			std::cerr << "Failed to open " << filename << " for writing\n";
			continue;
		}

		output_file.write(reinterpret_cast<char*>(segments_[segment_index].start_ptr), used);
		if (output_file.bad())
		{
			std::cerr << "Error writing to file " << filename << "\n";
			continue;
		}

		std::cout << "  Successfully wrote " << used << " bytes to disk\n";
	}
}

bool PcapShmWriterDevice::open()
{
	std::cout << (autotest_ ? "[AUTOTEST]:" : "[DATAPLANE]");
	std::cout << "Opening PcapShmWriterDevice\n";

	if (m_DeviceOpened)
	{
		std::cout << "Device already opened\n";
		return true;
	}

	switch (link_layer_type_)
	{
		case LINKTYPE_RAW:
		case LINKTYPE_DLT_RAW2:
			std::cerr << "Unsupported raw link layer type\n";
			return false;
		default:
			break;
	}

#if defined(PCAP_TSTAMP_PRECISION_NANO)
	m_PcapDescriptor = internal::PcapHandle(pcap_open_dead_with_tstamp_precision(
	        link_layer_type_, PCPP_MAX_PACKET_SIZE - 1, static_cast<int>(precision_)));
#else
	m_PcapDescriptor = internal::PcapHandle(pcap_open_dead(link_layer_type_, PCPP_MAX_PACKET_SIZE - 1));
#endif

	if (m_PcapDescriptor == nullptr)
	{
		std::cerr << "Failed to create pcap descriptor\n";
		return false;
	}
	std::cout << "Pcap descriptor created successfully\n";

	if (!FillSegments())
	{
		return false;
	}

	current_segment_index_ = 0;
	m_DeviceOpened = true;
	std::cout << "Device opened successfully\n";
	return true;
}

bool PcapShmWriterDevice::WritePacket(RawPacket const& packet)
{
	std::cout << (autotest_ ? "[AUTOTEST]:" : "[DATAPLANE]");
	std::cout << "\nWriting packet to shared memory\n";

	if (!m_DeviceOpened)
	{
		std::cerr << "Device not opened\n";
		++num_of_packets_not_written_;
		return false;
	}

	if (packet.getLinkLayerType() != link_layer_type_)
	{
		std::cerr << "Packet link layer type mismatch\n";
		++num_of_packets_not_written_;
		return false;
	}

	pcap_pkthdr pkt_hdr;
	pkt_hdr.caplen = packet.getRawDataLen();
	pkt_hdr.len = packet.getFrameLength();

	std::cout << "Packet details:\n";
	std::cout << "  Captured length: " << pkt_hdr.caplen << "\n";
	std::cout << "  Original length: " << pkt_hdr.len << "\n";

	timespec packet_timestamp = packet.getPacketTimeStamp();
#if defined(PCAP_TSTAMP_PRECISION_NANO)
	if (precision_ != FileTimestampPrecision::Nanoseconds)
	{
		TIMESPEC_TO_TIMEVAL(&pkt_hdr.ts, &packet_timestamp);
	}
	else
	{
		pkt_hdr.ts.tv_sec = packet_timestamp.tv_sec;
		pkt_hdr.ts.tv_usec = packet_timestamp.tv_nsec;
	}
#else
	TIMESPEC_TO_TIMEVAL(&pkt_hdr.ts, &packet_timestamp);
#endif

	std::cout << "  Timestamp: " << pkt_hdr.ts.tv_sec << "." << pkt_hdr.ts.tv_usec << "\n";

	size_t needed = kPcapPacketHeaderSizeOnDisk + pkt_hdr.caplen;
	std::cout << "  Space needed: " << needed << " bytes\n";

	FILE* file = segments_[current_segment_index_].file;
	long used = ftell(file);
	if (used < 0)
	{
		std::cerr << "ftell failed\n";
		++num_of_packets_not_written_;
		return false;
	}
	std::cout << "  Current segment usage: " << used << "/" << segments_[current_segment_index_].size << " bytes\n";

	size_t available = segments_[current_segment_index_].size - used;
	if (needed > available)
	{
		std::cout << "Not enough space, rotating to next segment\n";
		if (!RotateToNextSegment())
		{
			std::cerr << "Segment rotation failed\n";
			++num_of_packets_not_written_;
			return false;
		}
		file = segments_[current_segment_index_].file;
	}

	std::cout << "Writing packet to segment " << current_segment_index_ << "\n";
	pcap_dump(reinterpret_cast<uint8_t*>(segments_[current_segment_index_].dumper), &pkt_hdr, packet.getRawData());
	++num_of_packets_written_;

	std::cout << "Packet written successfully. Total packets written: " << num_of_packets_written_ << "\n";
	return true;
}

bool PcapShmWriterDevice::WritePackets(RawPacketVector const& packets)
{
	std::cout << "\nWriting " << packets.size() << " packets to shared memory\n";
	std::cout << "Current segment: " << current_segment_index_ << "\n";
	std::cout << "Packets written so far: " << num_of_packets_written_ << "\n";
	std::cout << "Packets failed so far: " << num_of_packets_not_written_ << "\n";

	size_t i = 0;
	for (RawPacket const* packet : packets)
	{
		std::cout << "\nProcessing packet " << i << " of " << packets.size() << "\n";
		if (!WritePacket(*packet))
		{
			std::cout << "Failed to write packet " << i << ", aborting batch\n";
			return false;
		}
		i++;
	}

	std::cout << "Successfully wrote " << packets.size() << " packets\n";
	return true;
}

void PcapShmWriterDevice::Flush()
{
	std::cout << (autotest_ ? "[AUTOTEST]:" : "[DATAPLANE]");
	std::cout << "\nFlushing all segments\n";

	if (!m_DeviceOpened)
	{
		std::cout << "Device not opened, nothing to flush\n";
		return;
	}

	std::cout << "Flushing " << segments_.size() << " segments\n";

	for (size_t i = 0; i < segments_.size(); ++i)
	{
		auto& seg = segments_[i];
		std::cout << "Segment " << i << " (dumper: " << seg.dumper << "): ";

		if (seg.dumper != nullptr)
		{
			if (pcap_dump_flush(seg.dumper) == -1)
			{
				std::cerr << "Flush failed\n";
			}
			else
			{
				std::cout << "Flush succeeded\n";
			}
		}
		else
		{
			std::cout << "No dumper\n";
		}
	}

	for (size_t i = 0; i < segments_.size(); ++i)
	{
		auto& seg = segments_[i];
		std::cout << "Segment " << i << " (file: " << seg.file << "): ";

		if (seg.file != nullptr)
		{
			if (fflush(seg.file) == EOF)
			{
				std::cerr << "File flush failed\n";
			}
			else
			{
				std::cout << "File flush succeeded\n";
			}
		}
		else
		{
			std::cout << "No file\n";
		}
	}

	std::cout << "Finished flushing all segments\n";
}

void PcapShmWriterDevice::close()
{
	std::cout << (autotest_ ? "[AUTOTEST]:" : "[DATAPLANE]");
	std::cout << "\nClosing device\n";
	std::cout << "Device opened: " << std::boolalpha << m_DeviceOpened << "\n";
	std::cout << "Current segment: " << current_segment_index_ << "\n";
	std::cout << "Packets written: " << num_of_packets_written_ << "\n";
	std::cout << "Packets failed: " << num_of_packets_not_written_ << "\n";

	if (!m_DeviceOpened)
	{
		std::cout << "Device already closed\n";
		return;
	}

	Flush();

	std::cout << "Closing " << segments_.size() << " segments\n";
	for (size_t i = 0; i < segments_.size(); ++i)
	{
		auto& seg = segments_[i];
		std::cout << "Segment " << i << " (dumper: " << seg.dumper << ", file: " << seg.file << "): ";

		if (seg.dumper != nullptr)
		{
			pcap_dump_close(seg.dumper);
			seg.start_ptr = nullptr;
			seg.size = 0;
			seg.dumper = nullptr;
			seg.file = nullptr;
			std::cout << "Closed\n";
		}
		else
		{
			std::cout << "No dumper to close\n";
		}
	}

	m_PcapDescriptor.reset();
	m_DeviceOpened = false;
	std::cout << "Device closed successfully\n";
}

void PcapShmWriterDevice::getStatistics(PcapStats& stats) const
{
	std::cout << "\nGetting statistics:\n";
	std::cout << "  Packets received: " << num_of_packets_written_ << "\n";
	std::cout << "  Packets dropped: " << num_of_packets_not_written_ << "\n";

	stats.packetsRecv = num_of_packets_written_;
	stats.packetsDrop = num_of_packets_not_written_;
	stats.packetsDropByInterface = 0;
}

void PcapShmWriterDevice::Clean()
{
	num_of_packets_not_written_ = 0;
	num_of_packets_written_ = 0;

	close();
	open();
}

IShmWriterDevice::IShmWriterDevice(void* shm_ptr, size_t shm_size) :
        IShmDevice(shm_ptr, shm_size) {}

PcapShmWriterDevice::PcapReaderPtr PcapShmWriterDevice::CreatePcapReader(const SegmentInfo& segment) const
{
	std::cout << "\nCreating pcap reader for segment:\n";
	std::cout << "  Start ptr: " << segment.start_ptr << "\n";
	std::cout << "  Size: " << segment.size << " bytes\n";

	std::string errbuf(PCAP_ERRBUF_SIZE, '\0');
	FILE* segment_file = fmemopen(segment.start_ptr, segment.size, "r");

	if (!segment_file)
	{
		std::cerr << "fmemopen failed for segment ["
		          << segment.start_ptr << ", " << segment.size << "]\n";
		std::abort();
	}
	std::cout << "  File handle created: " << segment_file << "\n";

	pcap_t* pcap_file = pcap_fopen_offline_with_tstamp_precision(
	        segment_file, static_cast<int>(precision_), errbuf.data());

	if (!pcap_file)
	{
		std::cerr << "pcap_fopen_offline failed: " << errbuf << "\n";
		std::abort();
	}
	std::cout << "  Pcap reader created: " << pcap_file << "\n";

	auto desctructor = [](pcap_t* p) {
		std::cout << "Destroying pcap reader: " << p << "\n";
		if (p)
			pcap_close(p);
	};

	return {pcap_file, desctructor};
}

int PcapShmWriterDevice::CountPacketsInSegment(const SegmentInfo& segment) const
{
	std::cout << "\nCounting packets in segment:\n";
	std::cout << "  Start ptr: " << segment.start_ptr << "\n";
	std::cout << "  Size: " << segment.size << " bytes\n";

	int packet_count = 0;
	pcap_pkthdr* header = nullptr;
	const u_char* packet_data = nullptr;

	PcapReaderPtr pcap_reader = CreatePcapReader(segment);

	std::cout << "Scanning for packets...\n";
	while (pcap_next_ex(pcap_reader.get(), &header, &packet_data) == 1)
	{
		if (header && header->caplen > 0)
		{
			std::cout << "  Packet " << packet_count << ":\n";
			std::cout << "    Timestamp: " << header->ts.tv_sec << "." << header->ts.tv_usec << "\n";
			std::cout << "    Captured length: " << header->caplen << "\n";
			std::cout << "    Original length: " << header->len << "\n";

			if (header->caplen <= 86) // Only dump small packets
			{
				std::cout << "    Packet data:\n";
				HexDump(packet_data, header->caplen, "      ");
			}
			else
			{
				std::cout << "    Packet data (first 64 bytes):\n";
				HexDump(packet_data, 64, "      ");
			}

			packet_count++;
		}
	}

	std::cout << "Found " << packet_count << " packets in segment\n";
	return packet_count;
}

PcapShmWriterDevice::PacketLocation PcapShmWriterDevice::LocatePacketInSegments(unsigned pkt_number) const
{
	std::cout << "\nLocating packet " << pkt_number << " in segments\n";
	std::cout << "Current segment index: " << current_segment_index_ << "\n";
	std::cout << "Total segments: " << pcap_files_ << "\n";

	size_t total_packets = 0;
	PacketLocation location = {0, 0, 0, false};

	for (size_t i = 0; i < pcap_files_; ++i)
	{
		size_t segment_index = (current_segment_index_ + 1 + i) % pcap_files_;
		std::cout << "Checking segment " << segment_index << "\n";

		int segment_packets = CountPacketsInSegment(segments_[segment_index]);
		std::cout << "  Segment contains " << segment_packets << " packets\n";
		std::cout << "  Total packets so far: " << total_packets << "\n";

		if (pkt_number < total_packets + segment_packets)
		{
			location.segment_index = segment_index;
			location.packet_offset = pkt_number - total_packets;
			location.total_packets = total_packets + segment_packets;
			location.found = true;

			std::cout << "  Found packet in segment " << segment_index
			          << " at offset " << location.packet_offset << "\n";
			return location;
		}

		total_packets += segment_packets;
	}

	location.total_packets = total_packets;
	std::cout << "Packet not found. Total packets available: " << total_packets << "\n";
	return location;
}

bool PcapShmWriterDevice::ReadPacketFromSegment(RawPacket& raw_packet, const PacketLocation& location) const
{
	std::cout << "\nReading packet from segment " << location.segment_index
	          << " at offset " << location.packet_offset << "\n";

	PcapReaderPtr pcap_reader = CreatePcapReader(segments_[location.segment_index]);

	pcap_pkthdr* header = nullptr;
	const u_char* packet_data = nullptr;
	size_t packets_skipped = 0;

	std::cout << "Skipping to requested packet...\n";
	while (true)
	{
		int result = pcap_next_ex(pcap_reader.get(), &header, &packet_data);

		if (result == 1)
		{
			if (packets_skipped == location.packet_offset)
			{
				std::cout << "Found target packet:\n";
				std::cout << "  Timestamp: " << header->ts.tv_sec << "." << header->ts.tv_usec << "\n";
				std::cout << "  Captured length: " << header->caplen << "\n";
				std::cout << "  Original length: " << header->len << "\n";

				if (header->caplen <= 64) // Only dump small packets
				{
					std::cout << "  Packet data:\n";
					HexDump(packet_data, header->caplen, "    ");
				}

				std::cout << "Copying packet data to RawPacket\n";
				raw_packet.reallocateData(header->caplen);
				raw_packet.appendData(packet_data, header->caplen);
				raw_packet.setPacketTimeStamp(header->ts);

				std::cout << "Packet read successfully\n";
				return true;
			}
			packets_skipped++;
		}
		else if (result == -1)
		{
			std::cerr << "Error reading packet: " << pcap_geterr(pcap_reader.get()) << "\n";
			return false;
		}
		else if (result == -2)
		{
			std::cerr << "Reached end of segment unexpectedly\n";
			return false;
		}
	}
}

bool PcapShmWriterDevice::GetPacket(RawPacket& raw_packet, unsigned pkt_number) const
{
	std::cout << (autotest_ ? "[AUTOTEST]:" : "[DATAPLANE]");
	std::cout << "\nGetPacket request for packet number " << pkt_number << "\n";

	if (!m_DeviceOpened)
	{
		std::cerr << "Device not opened\n";
		return false;
	}

	PacketLocation location = LocatePacketInSegments(pkt_number);
	if (!location.found)
	{
		std::cerr << "Requested packet number " << pkt_number
		          << " exceeds total available packets (" << location.total_packets << ")\n";
		return false;
	}

	return ReadPacketFromSegment(raw_packet, location);
}

} // namespace pcpp
