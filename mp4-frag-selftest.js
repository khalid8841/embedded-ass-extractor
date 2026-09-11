const assert=require('assert');
const {extractMp4Tracks}=require('./mp4-subtitles');
function box(type,payload){const b=Buffer.alloc(8+payload.length);b.writeUInt32BE(b.length,0);b.write(type,4);payload.copy(b,8);return b;}
function full(vf,p){const b=Buffer.alloc(4+p.length);b.writeUInt32BE(vf,0);p.copy(b,4);return b;}
function mdhd(){const p=Buffer.alloc(24);p.writeUInt32BE(0,0);p.writeUInt32BE(1000,12);p.writeUInt16BE((1<<10)|(18<<5)|1,20);return box('mdhd',p);}
function hdlr(){const p=Buffer.alloc(24);p.write('subt',8);return box('hdlr',p);}
function tkhd(){const p=Buffer.alloc(20);p.writeUInt32BE(0,0);p.writeUInt32BE(1,12);return box('tkhd',p);}
function stsd(){const p=Buffer.alloc(8);p.writeUInt32BE(1,4);const e=Buffer.alloc(16);e.writeUInt32BE(16);e.write('stpp',4);return box('stsd',Buffer.concat([p,e]));}
const stbl=box('stbl',stsd());
const mdia=box('mdia',Buffer.concat([mdhd(),hdlr(),box('minf',stbl)]));
const trak=box('trak',Buffer.concat([tkhd(),mdia]));
const moov=box('moov',trak);
function tfhd(){let p=Buffer.alloc(8);p.writeUInt32BE(0x020000,0);p.writeUInt32BE(1,4);return box('tfhd',p);}
function tfdt(){return box('tfdt',full(0,Buffer.from([0,0,0,0])));}
function trun(moofSize,sampleSize){let p=Buffer.alloc(20);p.writeUInt32BE(0x000301,0);p.writeUInt32BE(1,4);p.writeInt32BE(moofSize+8,8);p.writeUInt32BE(1000,12);p.writeUInt32BE(sampleSize,16);return box('trun',p);}
const sample=Buffer.from('<tt><body><p>مرحبا</p></body></tt>');
const traf0=Buffer.concat([tfhd(),tfdt()]);
let moof=box('moof',box('traf',Buffer.concat([traf0,trun(0,sample.length)])));
// trun data_offset is relative to moof start; sample is mdat payload.
moof=box('moof',box('traf',Buffer.concat([tfhd(),tfdt(),trun(moof.length,sample.length)])));
const mdat=box('mdat',sample);
const file=Buffer.concat([box('ftyp',Buffer.from('isom0000')),moov,moof,mdat]);
const safeFetch=async(url,opts)=>{
 const range=opts.headers.Range || opts.headers.range; const m=range.match(/bytes=(\d+)-(\d+)/); const s=Number(m[1]),e=Math.min(Number(m[2]),file.length-1);
 return new Response(file.slice(s,e+1),{status:206,headers:{'Content-Range':`bytes ${s}-${e}/${file.length}`,'Content-Length':String(e-s+1)}});
};
(async()=>{const tracks=await extractMp4Tracks(safeFetch,'https://x.test/a.mp4','fragtest');assert.equal(tracks.length,1);assert.equal(tracks[0].type,'stpp');assert.equal(tracks[0].cues.length,1);assert.equal(tracks[0].cues[0].text,'مرحبا');console.log('MP4 fragmented selftest: PASS');})().catch(e=>{console.error(e);process.exit(1)});
