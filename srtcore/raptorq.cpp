/*
 * jjustman@onemediallc.com
 * 2020-09-16
 * 
 */

#include <string>
#include <map>
#include <vector>
#include <deque>

#include "packetfilter.h"
#include "core.h"
#include "packet.h"
#include "logging.h"

#include "raptorq.h"

using namespace std;
using namespace srt_logging;

/*
 *  ,
    , rcv(provided)
 */
RaptorQFilterBuiltin::RaptorQFilterBuiltin(const SrtFilterInitializer &init, std::vector<SrtPacket> &provided, const string &confstr)
    : SrtPacketFilterBase(init)
    , m_fallback_level(SRT_ARQ_ONREQ)
	, rebuilt(provided)

{
    if (!ParseFilterConfig(confstr, cfg))
        throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);


	string source_block_size_string = map_get(cfg.parameters, "source_block_size");
	string symbol_size_string = map_get(cfg.parameters, "symbol_size");
	string recovery_symbols_string = map_get(cfg.parameters, "recovery_symbols");

	m_source_block_size = atoi(source_block_size_string.c_str());
	m_symbol_size = atoi(symbol_size_string.c_str()) + 16; //include packet header in raptorQ recovery
	m_recovery_symbols = atoi(recovery_symbols_string.c_str());

	m_source_symbols = m_source_block_size / m_symbol_size;

	encoder = new RaptorQEncoder;
	decoder = new RaptorQDecoder;

	encoder->init(m_source_block_size, m_symbol_size, m_recovery_symbols);
	decoder->init(m_source_block_size, m_symbol_size, m_recovery_symbols);


//
//    string arspec = map_get(cfg.parameters, "layout");
//
//    string shorter = arspec.size() > 5 ? arspec.substr(0, 5) : arspec;
//    if (shorter == "even")
//        m_arrangement_staircase = false;
//    else if (shorter != "" && shorter != "stair")
//    {
//        LOGC(mglog.Error, log << "FILTER/FEC: CONFIG: value for 'layout' must be 'even' or 'staircase'");
//        throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);
//    }
//
//    string colspec = map_get(cfg.parameters, "cols"), rowspec = map_get(cfg.parameters, "rows");
//
//    int out_rows = 1;
//    int out_cols = atoi(colspec.c_str());
//
//    if (colspec == "" || out_cols < 2)
//    {
//        LOGC(mglog.Error, log << "FILTER/FEC: CONFIG: at least 'cols' must be specified and > 1");
//        throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);
//    }
//
//    m_number_cols = out_cols;
//
//    if (rowspec != "")
//    {
//        out_rows = atoi(rowspec.c_str());
//        if (out_rows >= -1 && out_rows < 1)
//        {
//            LOGC(mglog.Error, log << "FILTER/FEC: CONFIG: 'rows' must be >=1 or negative < -1");
//            throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);
//        }
//    }
//
//    if (out_rows < 0)
//    {
//        m_number_rows = -out_rows;
//        m_cols_only = true;
//    }
//    else
//    {
//        m_number_rows = out_rows;
//        m_cols_only = false;
//    }

    // Extra interpret level, if found, default never.
    // Check only those that are managed.
    string level = cfg.parameters["arq"];
    int lv = -1;
    if (level != "")
    {
        static const char* levelnames [] = { "never", "onreq", "always" };

        for (size_t i = 0; i < Size(levelnames); ++i)
        {
            if (level == levelnames[i])
            {
                lv = i;
                break;
            }
        }

        if (lv == -1)
        {
            LOGC(mglog.Error, log << "FILTER/FEC: CONFIG: 'arq': value '" << level << "' unknown");
            throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);
        }

        m_fallback_level = SRT_ARQLevel(lv);
    }
    else
    {
        m_fallback_level = SRT_ARQ_ONREQ;
    }


//    // Required to store in the header when rebuilding
//    rcv.id = socketID();
//
//    // Setup the bit matrix, initialize everything with false.
//
//    // Vertical size (y)
//    rcv.cells.resize(sizeCol() * sizeRow(), false);
//
//    // These sequence numbers are both the value of ISN-1 at the moment
//    // when the handshake is done. The sender ISN is generated here, the
//    // receiver ISN by the peer. Both should be known after the handshake.
//    // Later they will be updated as packets are transmitted.
//
//    int32_t snd_isn = CSeqNo::incseq(sndISN());
//    int32_t rcv_isn = CSeqNo::incseq(rcvISN());
//
//    // Alright, now we need to get the ISN from m_parent
//    // to extract the sequence number allowing qualification to the group.
//    // The base values must be prepared so that feedSource can qualify them.
//
//    // SEPARATE FOR SENDING AND RECEIVING!
//
//    // Now, assignment of the groups requires:
//    // For row groups, simply the size of the group suffices.
//    // For column groups, you need a whole matrix of all sequence
//    // numbers that are base sequence numbers for the group.
//    // Sequences that belong to this group are:
//    // 1. First packet has seq+1 towards the base.
//    // 2. Every next packet has this value + the size of the row group.
//    // So: group dispatching is:
//    //  - get the column number
//    //  - extract the group data for that column
//    //  - check if the sequence is later than the group base sequence, if not, report no group for the packet
//    //  - sanity check, if the seqdiff divided by row size gets 0 remainder
//    //  - The result from the above division can't exceed the column size, otherwise
//    //    it's another group. The number of currently collected data should be in 'collected'.
//
//    // Now set up the group starting sequences.
//    // The very first group in both dimensions will have the value of ISN in particular direction.
//
//    // Set up sender part.
//    //
//    // Size: rows
//    // Step: 1 (next packet in group is 1 past the previous one)
//    // Slip: rows (first packet in the next group is distant to first packet in the previous group by 'rows')
//    HLOGC(mglog.Debug, log << "FEC: INIT: ISN { snd=" << snd_isn << " rcv=" << rcv_isn << " }; sender single row");
//    ConfigureGroup(snd.row, snd_isn, 1, sizeRow());
//
//    // In the beginning we need just one reception group. New reception
//    // groups will be created in tact with receiving packets outside this one.
//    // The value of rcv.row[0].base will be used as an absolute base for calculating
//    // the index of the group for a given received packet.
//    rcv.rowq.resize(1);
//    HLOGP(mglog.Debug, "FEC: INIT: receiver first row");
//    ConfigureGroup(rcv.rowq[0], rcv_isn, 1, sizeRow());
//
//    if (sizeCol() > 1)
//    {
//        // Size: cols
//        // Step: rows (the next packet in the group is one row later)
//        // Slip: rows+1 (the first packet in the next group is later by 1 column + one whole row down)
//
//        HLOGP(mglog.Debug, "FEC: INIT: sender first N columns");
//        ConfigureColumns(snd.cols, snd_isn);
//        HLOGP(mglog.Debug, "FEC: INIT: receiver first N columns");
//        ConfigureColumns(rcv.colq, rcv_isn);
//    }
//
//    // The bit markers that mark the received/lost packets will be expanded
//    // as packets come in.
//    rcv.cell_base = rcv_isn;
}

void RaptorQEncoder::init(size_t source_block_size, size_t symbol_size, int recovery_symbols) {
	m_source_block_size = source_block_size;
	m_symbol_size = symbol_size;
	m_recovery_symbols = recovery_symbols;
	m_source_symbols = m_source_block_size / m_symbol_size;

	printf("RaptorQEncoder::init, m_source_block_size: %d, m_symbol_size: %d, m_source_symbols: %d, m_recovery_symbols: %d",
			m_source_block_size,
			m_symbol_size,
			m_source_symbols,
			m_recovery_symbols);

	const int K = m_source_symbols;
	const int nSymSize = m_symbol_size;

	const int R = m_recovery_symbols;

	int ret = RqInterGetMemSizes(K, RQ_DEFAULT_MAX_EXTRA, &nInterWorkMemSize, &nInterProgMemSize, &nInterSymNumForExec);

	printf("Return value: %d\n", ret);
	printf("nInterWorkMemSize: %zd\n",	 nInterWorkMemSize);
	printf("nInterProgMemSize: %zd\n", 	 nInterProgMemSize);
	printf("nInterSymNumForExec: %zd\n", nInterSymNumForExec);

	pInterWorkMem = static_cast<RqInterWorkMem*>(calloc(nInterWorkMemSize, sizeof(void*)));
	pInterProgMem = static_cast<RqInterProgram*>(calloc(nInterProgMemSize, sizeof(void*)));

	nInterSymMemSize = nInterSymNumForExec * nSymSize;
	pInterSymMem = static_cast<RqInterWorkMem*>(calloc(nInterSymMemSize, sizeof(void*)));

	nInSymMemSize = K * nSymSize; //e.g. 65535 bytes
	pcInSymMem = static_cast<uint8_t*>(calloc(nInSymMemSize, sizeof(uint8_t)));

	ret = RqOutGetMemSizes(R, &nOutWorkMemSize, &nOutProgMemSize);

	pOutWorkMem = static_cast<RqOutWorkMem*>(calloc(nOutWorkMemSize, sizeof(void*)));
	pOutProgMem = static_cast<RqOutProgram*>(calloc(nOutProgMemSize, sizeof(void*)));

	nOutSymMemSize = R * nSymSize;

	pOutSymMem = static_cast<uint8_t*>(calloc(nOutSymMemSize, sizeof(uint8_t)));

	ret = RqInterInit(K, 0, pInterWorkMem, nInterWorkMemSize);
	printf("RqInterInit: Return value: %d\n", ret);

	ret = RqInterAddIds(pInterWorkMem, 0, K);
	printf("RqInterAddIds: Return value: %d\n", ret);

	ret = RqInterCompile(pInterWorkMem, pInterProgMem, nInterProgMemSize);
	printf("RqInterCompile: Return value: %d\n", ret);

	ret = RqOutInit(K, pOutWorkMem, nOutWorkMemSize);
	printf("RqOutInit: Return value: %d\n", ret);

	ret = RqOutAddIds(pOutWorkMem, K, R);
	printf("RqOutAddIds: Return value: %d\n", ret);

	ret = RqOutCompile(pOutWorkMem, pOutProgMem, nOutProgMemSize);
	printf("RqOutCompile: Return value: %d\n", ret);

}

void RaptorQEncoder::encode(uint32_t sbn) {
	int ret = 0;

	if(nControlPacketPosition != -1 && nControlPacketPosition != m_recovery_symbols) {
		printf("RaptorQEncoder::encode - WARNING - entering encode (new sbn: %d) with nControlPacketPosition: %d, nSbnPOut: %d, but expected to have built %d m_recovery_symbols control packets",
				sbn,
				nControlPacketPosition,
				nSbnPOutSysMem,
				m_recovery_symbols);

	}

	ret = RqInterExecute(pInterProgMem, m_symbol_size, pcInSymMem, nInSymMemSize, pInterSymMem, nInterSymMemSize);
	//generate the intermediate symbols from the compiled intermediate program and the source symbols.

	printf("RqInterExecute: Return value: %d\n", ret);

	ret = RqOutExecute(pOutProgMem, m_symbol_size, pInterSymMem, (void*)pOutSymMem, nOutSymMemSize);

	printf("RqOutExecute: Return value: %d\n", ret);

//	printf("Source Packet(s):\n");
//
//	for(int k=0; k < 1; k++) {
//		printf("Packet %d: ", k);
//		for(int j=0; j < nSymSize; j++) {
//			if(pcInSymMem[(k*nSymSize)+j] != 0) {
//				printf("s[%04d]:0x%02x ", j, pcInSymMem[(k*nSymSize)+j]);
//			}
//
//		}
//		printf("\n\n");
//	}
//
//	printf("Recovery Packet(s):\n");
//	for(int k=0; k < R; k++) {
//		printf("Packet %d: ", k);
//		for(int j=0; j < nSymSize; j++) {
//			if(pOutSymMem[(k*nSymSize)+j] != 0) {
//				printf("r[%04d]:0x%02x ", j, pOutSymMem[(k*nSymSize)+j]);
//			}
//
//		}
//		printf("\n\n");
//	}

	nControlPacketPosition = 0;
	nSbnPOutSysMem = sbn;
}

RaptorQEncoder::~RaptorQEncoder() {

	//jjustman-2020-09-16: todo - free calloc's


}


void RaptorQDecoder::init(size_t source_block_size, size_t symbol_size, int recovery_symbols) {

	m_source_block_size = source_block_size;
	m_symbol_size = symbol_size;
	m_recovery_symbols = recovery_symbols;
	m_source_symbols = m_source_block_size / m_symbol_size;

	printf("RaptorQDecoder::init, m_source_block_size: %d, m_symbol_size: %d, m_source_symbols: %d",
			m_source_block_size,
			m_symbol_size,
			m_source_symbols);


	int ret = 0;
	const int K = m_source_symbols;
	const int nSymSize = m_symbol_size;

	const int R = m_recovery_symbols;

	nMaxExtra = RQ_DEFAULT_MAX_EXTRA;

	ret = RqInterGetMemSizes(K, nMaxExtra, &nInterWorkMemSize, &nInterProgMemSize, &nInterSymNumForExec);
	printf("RqInterGetMemSizes: Return value: %d\n", ret);

	pInterWorkMem = static_cast<RqInterWorkMem*>(calloc(nInterWorkMemSize, sizeof(void*)));
	pInterProgMem = static_cast<RqInterProgram*>(calloc(nInterProgMemSize, sizeof(void*)));

	nInterSymMemSize = nInterSymNumForExec * nSymSize;
	pInterSymMem = static_cast<RqInterWorkMem*>(calloc(nInterSymMemSize, sizeof(void*)));

	nInSymMemSize = (K + nMaxExtra) * nSymSize; //e.g. 65535 bytes
	pcInSymMem = static_cast<uint8_t*>(calloc(nInSymMemSize, sizeof(uint8_t)));

	ret = RqOutGetMemSizes(K, &nOutWorkMemSize, &nOutProgMemSize);

	pOutWorkMem = static_cast<RqOutWorkMem*>(calloc(nOutWorkMemSize, sizeof(void*)));
	pOutProgMem = static_cast<RqOutProgram*>(calloc(nOutProgMemSize, sizeof(void*)));

	nOutSymMemSize = K * nSymSize;

	pOutSymMem = static_cast<uint8_t*>(calloc(nOutSymMemSize, sizeof(uint8_t)));

	ret = RqOutInit(K, pOutWorkMem, nOutWorkMemSize);
	printf("RqOutInit: Return value: %d\n", ret);

	ret = RqOutAddIds(pOutWorkMem, 0, K);
	printf("RqOutAddIds: Return value: %d\n", ret);

	ret = RqOutCompile(pOutWorkMem, pOutProgMem, nOutProgMemSize);
	printf("RqOutCompile: Return value: %d\n", ret);

}

void RaptorQDecoder::pushCPacket(uint32_t sbn, uint32_t esi, CPacket* cPacket) {

	if(esi >= m_source_symbols) {
		map<uint32_t, CPacket*>& sbnRef = sbnEsiCpacketRepair[sbn];
		CPacket* cpacketRef = sbnRef[esi];
		if(!cpacketRef) {
			sbnRef[esi] = cPacket;
		}
	} else {
		map<uint32_t, CPacket*>& sbnRef = sbnEsiCpacketSource[sbn];
		CPacket* cpacketRef = sbnRef[esi];
		if(!cpacketRef) {
			sbnRef[esi] = cPacket;
		}
	}
}

//if we have all of our source symbols, we do not need RQ Recovery
bool RaptorQDecoder::needsRQRecovery(uint32_t sbn) {
	pair<uint32_t, uint32_t> recoveredSbnSourceRepair = recoveredSbnSourceRepairCount[sbn];
	if(recoveredSbnSourceRepair.first && recoveredSbnSourceRepair.second) {
		return false;
	}

	map<uint32_t, CPacket*>& sbnRefSource = sbnEsiCpacketSource[sbn];

	return sbnRefSource.size() != m_source_symbols;
}

int RaptorQDecoder::getEsiSourceSize(uint32_t sbn) {
	map<uint32_t, CPacket*>& sbnRefSource = sbnEsiCpacketSource[sbn];

	return sbnRefSource.size();
}
//check if we can perform RQ recovery with M_symbols > Ksource_symbols
bool RaptorQDecoder::canPerformRQRecovery(uint32_t sbn) {
	map<uint32_t, CPacket*>& sbnRefSource = sbnEsiCpacketSource[sbn];
	map<uint32_t, CPacket*>& sbnRefRepair = sbnEsiCpacketRepair[sbn];

	return (sbnRefSource.size() + sbnRefRepair.size()) >= m_source_symbols;
}

int RaptorQDecoder::executeRQRecovery(uint32_t sbn) {
	int ret = 0;

	int sbn_esi_header_offset = 8;

	map<uint32_t, CPacket*>& sbnRefSource = sbnEsiCpacketSource[sbn];
	map<uint32_t, CPacket*>& sbnRefRepair = sbnEsiCpacketRepair[sbn];

	map<uint32_t, CPacket*>::iterator it;


	ret = RqInterInit(m_source_symbols, nMaxExtra, pInterWorkMem, nInterWorkMemSize);
	printf("RqInterInit: Return value: %d\n", ret);

	int inSymPosition = 0;
	for(it = sbnRefSource.begin(); it != sbnRefSource.end(); it++) {
		uint32_t esi = it->first;
		CPacket* pkt = it->second;

		//plus our 16 bytes for header as recoery, and 8 bytes for sbn/esi

		uint32_t seq_no = pkt->getHeader()[SRT_PH_SEQNO];
		uint32_t seq_no_net = htonl(seq_no);
		memcpy(&pcInSymMem[inSymPosition * m_symbol_size], &seq_no_net, 4);


		uint32_t msg_no = pkt->getHeader()[SRT_PH_MSGNO];
		uint32_t msg_no_net = htonl(msg_no);
		memcpy(&pcInSymMem[(inSymPosition * m_symbol_size)+4], &msg_no_net, 4);


		uint32_t timestamp = pkt->getHeader()[SRT_PH_TIMESTAMP];
		uint32_t timestamp_net = htonl(timestamp);
		memcpy(&pcInSymMem[(inSymPosition * m_symbol_size)+8], &timestamp_net, 4);


		uint32_t ph_id = pkt->getHeader()[SRT_PH_ID];
		uint32_t ph_id_net = htonl(ph_id);
		memcpy(&pcInSymMem[(inSymPosition * m_symbol_size)+12], &ph_id_net, 4);

		//remember, pkt->getData for source packets only contains sbn/esi
		memcpy(&pcInSymMem[(inSymPosition * m_symbol_size)+16], pkt->getData()+sbn_esi_header_offset, m_symbol_size);

		ret = RqInterAddIds(pInterWorkMem, esi, 1);
		printf("RqInterAddIds: (S) adding esi: %d, at pos: %d, ret: %d\n",
				esi,
				m_symbol_size * inSymPosition,
				ret);
		inSymPosition++;
	}

	for(it=sbnRefRepair.begin(); it != sbnRefRepair.end(); it++) {
		uint32_t esi = it->first;
		CPacket* pkt = it->second;

		//plus our 8 bytes for sbn/esi
		memcpy(&pcInSymMem[m_symbol_size * inSymPosition], pkt->getData()+8, m_symbol_size);
		ret = RqInterAddIds(pInterWorkMem, esi, 1);
		printf("RqInterAddIds: (R) adding esi: %d, at pos: %d, ret: %d\n",
				esi,
				m_symbol_size * inSymPosition,
				ret);
		inSymPosition++;
	}

	ret = RqInterCompile(pInterWorkMem, pInterProgMem, nInterProgMemSize);
	printf("RqInterCompile: Return value: %d\n", ret);

	ret = RqInterExecute(pInterProgMem, m_symbol_size, pcInSymMem, nInSymMemSize, pInterSymMem, nInterSymMemSize);
	printf("RqInterExecute: Return value: %d\n", ret);

	ret = RqOutExecute(pOutProgMem, m_symbol_size, pInterSymMem, pOutSymMem, nOutSymMemSize);
	printf("RqOutExecute: Return value: %d\n", ret);


	if(!ret) {
		recoveredSbnSourceRepairCount[sbn] = make_pair(sbnRefSource.size(), sbnRefRepair.size());
	}

	return ret;
}
void RaptorQDecoder::discardSbn(uint32_t sbn) {
	map<uint32_t, CPacket*>& sbnRefSource = sbnEsiCpacketSource[sbn];
	map<uint32_t, CPacket*>& sbnRefRepair = sbnEsiCpacketRepair[sbn];

	map<uint32_t, CPacket*>::iterator it;

	//jjustman-2020-09-17 - TODO - free CPackets
	for(it = sbnRefSource.begin(); it != sbnRefSource.end(); it++) {
		uint32_t esi = it->first;
		CPacket* pkt = it->second;
		delete pkt;
	}

	for(it = sbnRefRepair.begin(); it != sbnRefRepair.end(); it++) {
		uint32_t esi = it->first;
		CPacket* pkt = it->second;
		delete pkt;
	}

	sbnRefSource.clear();
	sbnRefRepair.clear();

}

pair<uint32_t, uint32_t> RaptorQDecoder::getRecoveredSbnSourceRepairCount(uint32_t sbn) {
	pair<uint32_t, uint32_t> sbnSourceRepairCount = recoveredSbnSourceRepairCount[sbn];
	return recoveredSbnSourceRepairCount[sbn];
}


RaptorQDecoder::~RaptorQDecoder() {

	//jjustman-2020-09-16: todo - free calloc's

}

void RaptorQFilterBuiltin::feedSource(CPacket& packet)
{
	int header_offset = 8;
	int32_t pktSeqNum = packet.getSeqNo();
	int32_t mySeqNum = 0;

	if(firstSeqNum == -1) {
		firstSeqNum = pktSeqNum;
	}

	//jjustman-2020-09-17 - TODO - handle wraparounds
	mySeqNum = pktSeqNum - firstSeqNum;

	//shift down our data for 8 bytes for sbn and esi
	int original_size = packet.size();

	packet.setLength(original_size+header_offset);
	int new_size = packet.size();
	char* data = packet.data();

	memmove(&data[header_offset], data, new_size);

	//printf("packet size: %d, last 2 bytes: 0x%02x, 0x%02x", packet.size(), data[size-2], data[size-1]);

	uint32_t sbn = mySeqNum / m_source_symbols;
	uint32_t esi = mySeqNum - (sbn * m_source_symbols);

	printf("pktSeqNum: %d, mySeqNum: %d, packet size: %d, new_size: %d sbn: %d (prev 0x%02x 0x%02x), esi: %d (prev 0x%02x 0x%02x)\n",
			pktSeqNum,
			mySeqNum,
			original_size,
			new_size,
			sbn,
			(uint8_t)data[0],
			(uint8_t)data[1],
			esi,
			(uint8_t)data[2],
			(uint8_t)data[3]);

	uint32_t sbn_nl = htonl(sbn);
	uint32_t esi_nl = htonl(esi);

	memcpy(&data[0], &sbn_nl, 4);
	memcpy(&data[4], &esi_nl, 4);


	//push into RaptorQEncoder pcInSymMem
	//jjustman-2020-09-17 - todo: hashmap based upon SBN

	/*
	 *   	SRT_PH_SEQNO = 0,     //< sequence number
    		SRT_PH_MSGNO = 1,     //< message number
    		SRT_PH_TIMESTAMP = 2, //< time stamp
    		SRT_PH_ID = 3,        //< socket ID

    // Must be the last value - this is size of all, not a field id
    SRT_PH_E_SIZE
	 */

	uint32_t seq_no = packet.getHeader()[SRT_PH_SEQNO];
	uint32_t seq_no_net = htonl(seq_no);
	memcpy(&encoder->pcInSymMem[esi * m_symbol_size], &seq_no_net, 4);


	uint32_t msg_no = packet.getHeader()[SRT_PH_MSGNO];
	uint32_t msg_no_net = htonl(msg_no);
	memcpy(&encoder->pcInSymMem[(esi * m_symbol_size)+4], &msg_no_net, 4);


	uint32_t timestamp = packet.getHeader()[SRT_PH_TIMESTAMP];
	uint32_t timestamp_net = htonl(timestamp);
	memcpy(&encoder->pcInSymMem[(esi * m_symbol_size)+8], &timestamp_net, 4);


	uint32_t ph_id = packet.getHeader()[SRT_PH_ID];
	uint32_t ph_id_net = htonl(ph_id);
	memcpy(&encoder->pcInSymMem[(esi * m_symbol_size)+12], &ph_id_net, 4);


	memcpy(&encoder->pcInSymMem[(esi * m_symbol_size)+16], &data[header_offset], m_symbol_size);

	if(esi == (m_source_symbols-1)) {
		//last block to copy, perform encode
		encoder->encode(sbn);
		//nControlPacketPosition will now be 0, and we can start pushing our repair symbols
	}
}


bool RaptorQFilterBuiltin::packControlPacket(SrtPacket& pkt, int32_t seq)
{

	//jjustman-2020-09-17 - todo : clamp m_symbol_size to MAX_PKT - 8
	if(encoder->nControlPacketPosition != -1 && encoder->nControlPacketPosition < m_recovery_symbols) {
		char* data = pkt.data();
		pkt.length = m_symbol_size + 8;
		//pkt.hdr[SRT_PH_SEQNO] = seq;
		pkt.hdr[SRT_PH_MSGNO] = SRT_MSGNO_CONTROL;

		//write our "sbn" and esi as m_source_symbols + nControlPacketPosition
		uint32_t sbn = encoder->nSbnPOutSysMem;
		uint32_t sbn_nl = htonl(sbn);
		uint32_t esi = m_source_symbols + encoder->nControlPacketPosition;
		uint32_t esi_nl = htonl(esi);

		memcpy(&data[0], &sbn_nl, 4);
		memcpy(&data[4], &esi_nl, 4);

		memcpy(&data[8], &encoder->pOutSymMem[encoder->nControlPacketPosition * m_symbol_size], m_symbol_size);
		printf("packControlPacket: adding control (R: %d) packet with sbn: %d, esi: %d\n",
				encoder->nControlPacketPosition,
				sbn,
				esi);

		encoder->nControlPacketPosition++;
		if(encoder->nControlPacketPosition == m_recovery_symbols) {
			encoder->nControlPacketPosition = -1; //sent all our recovery packets
		}

		return true;
	}

    return false;
}


bool RaptorQFilterBuiltin::receive(const CPacket& rpkt, loss_seqs_t& loss_seqs)
{

	int size = rpkt.size();
	const char* data = rpkt.data();
	int new_size = size - 8;

	int32_t seqNum = rpkt.getSeqNo();

	uint32_t sbn = ntohl(*((uint32_t*)(&data[0])));
	uint32_t esi = ntohl(*((uint32_t*)(&data[4])));

	//else - fake some packet loss
	int randPacketLoss = rand() % 100;
	if(randPacketLoss == 40) {
		printf("dropping packet: seqNum: %d, sbn: %d, esi: %d\n", seqNum, sbn, esi);
		return false;
	}

	//push this packet (and header/sbn/esi/etc into our collection for possible recovery
	decoder->pushCPacket(sbn, esi, rpkt.clone());

	//RQ only makes sense if we have at least one "control" (repair) packet present
	//jjustman-2020-09-17 - TODO: purge if we don't need RQ or if we would be otherwise incomplete RQ after exceeding our latency
	if (rpkt.getMsgSeq() == SRT_MSGNO_CONTROL) {
		bool needsRQRecoveryFlag = decoder->needsRQRecovery(sbn);
		bool canPerformRQRecoveryFlag = decoder->canPerformRQRecovery(sbn);

		printf("received control: seq: %d, sbn: %d, esi: %d (isR: %d), needsRQRecoveryFlag: %d (Msource: %d, Ksource: %d), canPerformRQRecoveryFlag: %d\n",
				seqNum,
				sbn,
				esi,
				esi >= m_source_symbols,
				needsRQRecoveryFlag,
				decoder->getEsiSourceSize(sbn),
				m_source_symbols,
				canPerformRQRecoveryFlag
				);

		if(needsRQRecoveryFlag) {

			//jjustman-2020-09-17 - yes i know its messy...
			if(canPerformRQRecoveryFlag) {
				int res = decoder->executeRQRecovery(sbn);
				if(res == 0) {
					//dispatch our rebuilt packets as needed where we are missing sbnEsiCpacketSource

					printf("RECOVER %d PACKETS FROM decoder->pOutSysMem\n", m_source_symbols - decoder->getEsiSourceSize(sbn));

					int lastEsi = -1;
					map<uint32_t, CPacket*>& sbnRefSource = decoder->sbnEsiCpacketSource[sbn];
					map<uint32_t, CPacket*>::iterator it;

					for(it = sbnRefSource.begin(); it != sbnRefSource.end(); it++) {
						uint32_t esi = it->first;
						CPacket* pkt = it->second;

						if(esi != (lastEsi + 1)) {
							for(int i=lastEsi + 1; i < esi && i < decoder->getKSourceSymbols(); i++) {
								int recoverEsi = i;
								//recover this packet;
								printf("Recover sbn: %d, esi: %d\n (last esi: %d, next esi: %d)", sbn, recoverEsi, lastEsi, esi);

								rebuilt.push_back( decoder->getSymbolSize()-16);

								PrivPacket& p = rebuilt.back();

								//jjustman-2020-09-17 - use HEADERS from our SRT recovered payload - first 16 bytes
								uint32_t seq_no_net = 0;
								memcpy(&seq_no_net, &decoder->pOutSymMem[(recoverEsi * decoder->getSymbolSize())], 4);
								uint32_t seq_no = ntohl(seq_no_net);

								uint32_t msg_no_net = 0;
								memcpy(&msg_no_net, &decoder->pOutSymMem[(recoverEsi * decoder->getSymbolSize())+4], 4);
								uint32_t msg_no = ntohl(msg_no_net);

								uint32_t timestamp_net = 0;
								memcpy(&timestamp_net, &decoder->pOutSymMem[(recoverEsi * decoder->getSymbolSize())+8], 4);
								uint32_t timestamp = ntohl(timestamp_net);

								uint32_t ph_id_net = 0;
								memcpy(&ph_id_net, &decoder->pOutSymMem[(recoverEsi * decoder->getSymbolSize())+12], 4);
								uint32_t ph_id = ntohl(ph_id_net);


								p.hdr[SRT_PH_SEQNO]     = seq_no;
								p.hdr[SRT_PH_MSGNO]		= msg_no;
								p.hdr[SRT_PH_TIMESTAMP] = timestamp;
								p.hdr[SRT_PH_ID] 		= ph_id;

								// This is for live mode only, for now, so the message
								// number will be always 1, PB_SOLO, INORDER, and flags from clip.
								// The REXMIT flag is set to 1 to fake that the packet was
								// retransmitted. It is necessary because this packet will
								// come out of sequence order, and if such a packet has
								// no rexmit flag set, it's treated as reordered by network,
								// which isn't true here.

								p.hdr[SRT_PH_MSGNO] = 1
								        | MSGNO_PACKET_BOUNDARY::wrap(PB_SOLO)

								        | MSGNO_REXMIT::wrap(true)
								        ;
								/*
								 *
								 * 								        | MSGNO_PACKET_INORDER::wrap(rcv.order_required)
								        | MSGNO_ENCKEYSPEC::wrap(g.flag_clip)

								p.hdr[SRT_PH_MSGNO] = rpkt.header(SRT_PH_MSGNO)

								        | MSGNO_PACKET_BOUNDARY::wrap(PB_SOLO)
								        | MSGNO_PACKET_INORDER::wrap(rcv.order_required)
								        | MSGNO_ENCKEYSPEC::wrap(g.flag_clip)
								        | MSGNO_REXMIT::wrap(true)
								        ;

								p.hdr[SRT_PH_TIMESTAMP] = rpkt.header(SRT_PH_TIMESTAMP);
								p.hdr[SRT_PH_ID] = rpkt.header(SRT_PH_ID);

								*/


								memcpy(p.buffer, &decoder->pOutSymMem[(recoverEsi * decoder->getSymbolSize())+16], (decoder->getSymbolSize()-16));


								printf("seqNum: %d, original packet size: %d, new size: %d, sbn_header: %d, esi_header: %d, seq_no: %d, timestamp: %d, first 4 bytes: 0x%02x 0x%02x 0x%02x 0x%02x\n",
											seqNum,
											size,
											new_size,
											sbn,
											recoverEsi,
											seq_no,
											timestamp,
											(uint8_t)p.buffer[0],
											(uint8_t)p.buffer[1],
											(uint8_t)p.buffer[2],
											(uint8_t)p.buffer[3]);

							}
						}

						lastEsi = esi;
					}

					decoder->discardSbn(sbn);
				}
			}
		}

		return false;
	}


	decoder->pushCPacket(sbn, esi, rpkt.clone());

	//otherwise, push this directly to our
	rebuilt.push_back( new_size );

	PrivPacket& p = rebuilt.back();

	p.hdr[SRT_PH_SEQNO] = rpkt.getSeqNo();

	// This is for live mode only, for now, so the message
	// number will be always 1, PB_SOLO, INORDER, and flags from clip.
	// The REXMIT flag is set to 1 to fake that the packet was
	// retransmitted. It is necessary because this packet will
	// come out of sequence order, and if such a packet has
	// no rexmit flag set, it's treated as reordered by network,
	// which isn't true here.
	p.hdr[SRT_PH_MSGNO] = rpkt.header(SRT_PH_MSGNO);

//	        | MSGNO_PACKET_BOUNDARY::wrap(PB_SOLO)
//	        | MSGNO_PACKET_INORDER::wrap(rcv.order_required)
//	        | MSGNO_ENCKEYSPEC::wrap(g.flag_clip)
//	        | MSGNO_REXMIT::wrap(true)
//	        ;

	p.hdr[SRT_PH_TIMESTAMP] = rpkt.header(SRT_PH_TIMESTAMP);
	p.hdr[SRT_PH_ID] = rpkt.header(SRT_PH_ID);

	    // Header ready, now we rebuild the contents
	    // First, rebuild the length.

	    // Allocate the buffer and assign to a packet.
	    // This is only temporary, it will be copied to
	    // the target place when needed, with the buffer coming
	    // from the unit queue.

	    // The payload clip may be longer than length_hw, but it
	    // contains only trailing zeros for completion, which are skipped.
	memcpy(p.buffer, &data[8], new_size);


	printf("seqNum: %d, original packet size: %d, new size: %d, sbn_header: %d, esi_header: %d, first 4 bytes: 0x%02x 0x%02x 0x%02x 0x%02x\n",
				seqNum,
				size,
				new_size,
				sbn,
				esi,
				(uint8_t)p.buffer[0],
				(uint8_t)p.buffer[1],
				(uint8_t)p.buffer[2],
				(uint8_t)p.buffer[3]
		);


	return false;
}

//
//void FECFilterBuiltin::CheckLargeDrop(int32_t seqno)
//{
//    // Ok, first try to pick up the column and series
//
//    int offset = CSeqNo::seqoff(rcv.rowq[0].base, seqno);
//    if (offset < 0)
//    {
//        return;
//    }
//
//    // For row-only configuration, check only parts referring
//    // to a row.
//    if (m_number_rows == 1)
//    {
//        // We have no columns. So just check if exceeds 5* the row size.
//        // If so, clear the rows and reconfigure them.
//        if (offset > int(5 * sizeRow()))
//        {
//            // Calculate the new row base, without breaking the current
//            // layout. Make a skip by some number of rows so that the new
//            // first row is prepared to receive this packet.
//
//            int32_t oldbase = rcv.rowq[0].base;
//            size_t rowdist = offset / sizeRow();
//            int32_t newbase = CSeqNo::incseq(oldbase, rowdist * sizeRow());
//
//            LOGC(mglog.Warn, log << "FEC: LARGE DROP detected! Resetting row groups. Base: %" << oldbase
//                    << " -> %" << newbase << "(shift by " << CSeqNo::seqoff(oldbase, newbase) << ")");
//
//            rcv.rowq.clear();
//            rcv.cells.clear();
//
//            rcv.rowq.resize(1);
//            HLOGP(mglog.Debug, "FEC: RE-INIT: receiver first row");
//            ConfigureGroup(rcv.rowq[0], newbase, 1, sizeRow());
//        }
//
//        return;
//    }
//
//    bool reset_anyway = false;
//    if (offset != CSeqNo::seqoff(rcv.colq[0].base, seqno))
//    {
//        reset_anyway = true;
//        HLOGC(mglog.Debug, log << "FEC: IPE: row.base %" << rcv.rowq[0].base << " != %" << rcv.colq[0].base << " - resetting");
//    }
//
//    // Number of column - regardless of series.
//    int colx = offset % numberCols();
//
//    // Base sequence from the group series 0 in this column
//
//    // [[assert rcv.colq.size() >= numberCols()]];
//    int32_t colbase = rcv.colq[colx].base;
//
//    // Offset between this base and seqno
//    int coloff = CSeqNo::seqoff(colbase, seqno);
//
//    // Might be that it's in the row above the column,
//    // still it's not a large-drop
//    if (coloff < 0)
//    {
//        return;
//    }
//
//    size_t matrix = numberRows() * numberCols();
//
//    int colseries = coloff / matrix;
//
//    if (colseries > 2 || reset_anyway)
//    {
//        // Ok, now define the new ABSOLUTE BASE. This is the base of the column 0
//        // column group from the series previous towards this one.
//        int32_t oldbase = rcv.colq[0].base;
//        int32_t newbase = CSeqNo::incseq(oldbase, (colseries-1) * matrix);
//
//        LOGC(mglog.Warn, log << "FEC: LARGE DROP detected! Resetting all groups. Base: %" << oldbase
//                << " -> %" << newbase << "(shift by " << CSeqNo::seqoff(oldbase, newbase) << ")");
//
//        rcv.rowq.clear();
//        rcv.colq.clear();
//        rcv.cells.clear();
//
//        rcv.rowq.resize(1);
//        HLOGP(mglog.Debug, "FEC: RE-INIT: receiver first row");
//        ConfigureGroup(rcv.rowq[0], newbase, 1, sizeRow());
//
//        // Size: cols
//        // Step: rows (the next packet in the group is one row later)
//        // Slip: rows+1 (the first packet in the next group is later by 1 column + one whole row down)
//        HLOGP(mglog.Debug, "FEC: RE-INIT: receiver first N columns");
//        ConfigureColumns(rcv.colq, newbase);
//
//        rcv.cell_base = newbase;
//    }
//}

//
//// Now all collected lost packets translate into the range list format
//TranslateLossRecords(loss, irrecover);
//
//HLOGC(mglog.Debug, log << "FEC: ... COLLECTED IRRECOVER: " << Printable(loss) << (any_dismiss ? " CELLS DISMISSED" : " nothing dismissed"));
//}
//
//void FECFilterBuiltin::TranslateLossRecords(const set<int32_t>& loss, loss_seqs_t& irrecover)
//{
//    if (loss.empty())
//        return;
//
//    // size() >= 1 granted
//    set<int32_t>::iterator i = loss.begin();
//
//    int32_t fi_start = *i;
//    int32_t fi_end = fi_start;
//    ++i;
//    for (; i != loss.end(); ++i)
//    {
//        int dist = CSeqNo::seqoff(fi_end, *i);
//        if (dist == 1)
//            ++fi_end;
//        else
//        {
//            // Jumped over some sequences, cut the range.
//            irrecover.push_back(make_pair(fi_start, fi_end));
//            fi_start = fi_end = *i;
//        }
//    }
//
//    // And ship the last one
//    irrecover.push_back(make_pair(fi_start, fi_end));
//}

