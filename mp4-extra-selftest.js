const assert = require('assert');
const { parseMoov, extractTextFromSample } = require('./mp4-subtitles');
function box(type,payload){const b=Buffer.alloc(8+payload.length);b.writeUInt32BE(b.length,0);b.write(type,4);payload.copy(b,8);return b;}
function stts(){const p=Buffer.alloc(8);p.writeUInt32BE(1,4);const e=Buffer.alloc(8);e.writeUInt32BE(1,0);e.writeUInt32BE(1000,4);return box('stts',Buffer.concat([p,e]));}
function stsc(){const p=Buffer.alloc(8);p.writeUInt32BE(1,4);const e=Buffer.alloc(12);e.writeUInt32BE(1,0);e.writeUInt32BE(1,4);e.writeUInt32BE(1,8);return box('stsc',Buffer.concat([p,e]));}
function stsz(){const p=Buffer.alloc(12);p.writeUInt32BE(0,4);p.writeUInt32BE(1,8);const e=Buffer.alloc(4);e.writeUInt32BE(5,0);return box('stsz',Buffer.concat([p,e]));}
function stco(off){const p=Buffer.alloc(8);p.writeUInt32BE(1,4);const e=Buffer.alloc(4);e.writeUInt32BE(off,0);return box('stco',Buffer.concat([p,e]));}
function stsd(type){const p=Buffer.alloc(8);p.writeUInt32BE(1,4);const e=Buffer.alloc(16);e.writeUInt32BE(16,0);e.write(type,4);return box('stsd',Buffer.concat([p,e]));}
function mdhd(){const p=Buffer.alloc(24);p.writeUInt32BE(0,0);p.writeUInt32BE(1000,12);p.writeUInt16BE((1<<10)|(18<<5)|1,20);return box('mdhd',p);}
function hdlr(){const p=Buffer.alloc(24);p.write('subt',8);return box('hdlr',p);}
function make(type){const stbl=box('stbl',Buffer.concat([stsd(type),stts(),stsc(),stsz(),stco(100)]));const minf=box('minf',stbl);const mdia=box('mdia',Buffer.concat([mdhd(),hdlr(),minf]));const trak=box('trak',mdia);return Buffer.concat([box('ftyp',Buffer.from('isom0000')),box('moov',trak)]);}
for (const type of ['tx3g','wvtt','stpp','sbtt','stxt']) {
  const p=parseMoov(make(type));
  assert.equal(p.tracks.length,1, type);
  assert.equal(p.tracks[0].format,type,type);
}
assert.equal(extractTextFromSample(Buffer.from([0,5,0x48,0x65,0x6c,0x6c,0x6f]),'tx3g'),'Hello');
assert.equal(extractTextFromSample(Buffer.from('Hello','utf8'),'wvtt'),'Hello');
const vttc=Buffer.concat([box('sttg',Buffer.from('00:00:01.000')),box('payl',Buffer.from('مرحبا'))]);
assert.equal(extractTextFromSample(box('vttc',vttc),'wvtt'),'مرحبا');
assert.equal(extractTextFromSample(Buffer.from('<tt><p>مرحبا &amp; أهلا</p></tt>','utf8'),'stpp'),'مرحبا & أهلا');
console.log('MP4 extra selftest: PASS');
