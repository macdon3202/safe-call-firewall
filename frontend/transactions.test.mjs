import test from'node:test';import assert from'node:assert/strict';import{normalizeHash,receiptState}from'./src/transactions.js';
test('normalizes hash shapes',()=>{const h='0x'+'ab'.repeat(32);assert.equal(normalizeHash({txId:h}),h)});
test('rejects bad wallet response',()=>assert.throws(()=>normalizeHash({hash:'bad'})));
test('FINALIZED execution error is failure',()=>assert.equal(receiptState({statusName:'FINALIZED',consensus_data:{leader_receipt:[{mode:'leader',execution_result:'ERROR'}]}}).accepted,false));
test('majority disagreement is failure',()=>assert.equal(receiptState({statusName:'FINALIZED',result_name:'MAJORITY_DISAGREE',consensus_data:{leader_receipt:[{mode:'leader',execution_result:'SUCCESS'}]}}).failed,true));
test('finalized leader success is accepted',()=>assert.equal(receiptState({statusName:'FINALIZED',result_name:'MAJORITY_AGREE',consensus_data:{leader_receipt:[{mode:'leader',execution_result:'SUCCESS'}]}}).accepted,true));
test('finalized without an affirmative consensus is failure',()=>assert.equal(receiptState({statusName:'FINALIZED',consensus_data:{leader_receipt:{mode:'leader',execution_result:'SUCCESS'}}}).failed,true));
test('supports object-shaped leader receipt',()=>assert.equal(receiptState({status_name:'FINALIZED',result_name:'AGREE',consensus_data:{leader_receipt:{mode:'leader',execution_result:'SUCCESS'}}}).accepted,true));
